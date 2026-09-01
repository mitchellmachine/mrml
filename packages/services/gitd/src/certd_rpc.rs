use std::path::{Path, PathBuf};

use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy,
    CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES, UnixCertdSession, decode_certd_channel_request,
    encode_certd_channel_request,
};

const IDENTITY_REQUEST_MAGIC: &[u8; 8] = b"MRGIDR01";
const IDENTITY_SNAPSHOT_MAGIC: &[u8; 8] = b"MRGIDS01";
const CERTIFICATE_VERIFY_REQUEST_MAGIC: &[u8; 8] = b"MRGSGN01";
const CERTIFICATE_VERIFY_RESPONSE_MAGIC: &[u8; 8] = b"MRGSGS01";
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const MAX_CERTIFICATE_VERIFY_SIGNATURE_BYTES: usize = 72;
const MAX_SERVER_NAME_BYTES: usize = 253;
const MAX_CERTIFICATE_CHAIN_ENTRIES: usize = 8;
const MAX_CERTIFICATE_DER_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_SCHEMES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitdIdentitySnapshot {
    pub server_name: String,
    pub identity_generation: u64,
    pub certificate_chain: Vec<Vec<u8>>,
    pub leaf_spki_sha256: [u8; 32],
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    pub signature_schemes: Vec<u16>,
    pub publication_digest: [u8; 32],
}

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

    pub fn get_identity_snapshot(
        &mut self,
        server_name: &str,
    ) -> Result<GitdIdentitySnapshot, GitdCertdChannelError> {
        let request = encode_identity_request(server_name)?;
        let mut output = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
        let written = self.exchange(
            CertdChannelOperation::GetIdentitySnapshot,
            &request,
            &mut output,
        )?;
        parse_identity_snapshot(&output[..written], server_name)
    }

    pub fn sign_tls13_certificate_verify(
        &mut self,
        identity_generation: u64,
        signature_scheme: u16,
        transcript_hash: [u8; 32],
        logical_request_id: u64,
    ) -> Result<Vec<u8>, GitdCertdChannelError> {
        if identity_generation == 0
            || signature_scheme != ECDSA_SECP256R1_SHA256
            || logical_request_id == 0
        {
            return Err(GitdCertdChannelError::Authenticate);
        }
        let mut request = Vec::with_capacity(58);
        request.extend_from_slice(CERTIFICATE_VERIFY_REQUEST_MAGIC);
        request.extend_from_slice(&identity_generation.to_be_bytes());
        request.extend_from_slice(&signature_scheme.to_be_bytes());
        request.extend_from_slice(&transcript_hash);
        request.extend_from_slice(&logical_request_id.to_be_bytes());
        let mut output = [0u8; 128];
        let written = self.exchange(
            CertdChannelOperation::SignTls13CertificateVerify,
            &request,
            &mut output,
        )?;
        parse_certificate_verify_response(
            &output[..written],
            identity_generation,
            signature_scheme,
            logical_request_id,
        )
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

fn encode_identity_request(server_name: &str) -> Result<Vec<u8>, GitdCertdChannelError> {
    validate_server_name(server_name)?;
    let length =
        u16::try_from(server_name.len()).map_err(|_| GitdCertdChannelError::OutputLimit)?;
    let mut output = Vec::with_capacity(10 + server_name.len());
    output.extend_from_slice(IDENTITY_REQUEST_MAGIC);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(server_name.as_bytes());
    Ok(output)
}

fn parse_identity_snapshot(
    input: &[u8],
    expected_server_name: &str,
) -> Result<GitdIdentitySnapshot, GitdCertdChannelError> {
    validate_server_name(expected_server_name)?;
    let mut cursor = SnapshotCursor { input, offset: 0 };
    if cursor.take(8)? != IDENTITY_SNAPSHOT_MAGIC {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let identity_generation = cursor.u64()?;
    if identity_generation == 0 {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let name_length = usize::from(cursor.u16()?);
    let server_name = core::str::from_utf8(cursor.take(name_length)?)
        .map_err(|_| GitdCertdChannelError::Authenticate)?;
    validate_server_name(server_name)?;
    if server_name != expected_server_name {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let chain_count = usize::from(cursor.u8()?);
    if !(1..=MAX_CERTIFICATE_CHAIN_ENTRIES).contains(&chain_count) {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let mut certificate_chain = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        let length =
            usize::try_from(cursor.u32()?).map_err(|_| GitdCertdChannelError::Authenticate)?;
        if length == 0 || length > MAX_CERTIFICATE_DER_BYTES {
            return Err(GitdCertdChannelError::Authenticate);
        }
        certificate_chain.push(cursor.take(length)?.to_vec());
    }
    let mut leaf_spki_sha256 = [0u8; 32];
    leaf_spki_sha256.copy_from_slice(cursor.take(32)?);
    let not_before_unix_seconds = cursor.u64()?;
    let not_after_unix_seconds = cursor.u64()?;
    if leaf_spki_sha256 == [0; 32]
        || not_before_unix_seconds == 0
        || not_after_unix_seconds <= not_before_unix_seconds
    {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let scheme_count = usize::from(cursor.u8()?);
    if !(1..=MAX_SIGNATURE_SCHEMES).contains(&scheme_count) {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let mut signature_schemes = Vec::with_capacity(scheme_count);
    for _ in 0..scheme_count {
        let scheme = cursor.u16()?;
        if scheme == 0 || signature_schemes.last().is_some_and(|last| *last >= scheme) {
            return Err(GitdCertdChannelError::Authenticate);
        }
        signature_schemes.push(scheme);
    }
    let mut publication_digest = [0u8; 32];
    publication_digest.copy_from_slice(cursor.take(32)?);
    if publication_digest == [0; 32] || cursor.u8()? != 1 || cursor.offset != input.len() {
        return Err(GitdCertdChannelError::Authenticate);
    }
    Ok(GitdIdentitySnapshot {
        server_name: server_name.to_owned(),
        identity_generation,
        certificate_chain,
        leaf_spki_sha256,
        not_before_unix_seconds,
        not_after_unix_seconds,
        signature_schemes,
        publication_digest,
    })
}

fn validate_server_name(server_name: &str) -> Result<(), GitdCertdChannelError> {
    if server_name.is_empty()
        || server_name.len() > MAX_SERVER_NAME_BYTES
        || server_name.starts_with('.')
        || server_name.ends_with('.')
        || server_name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label.bytes().any(|byte| {
                    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-'
                })
        })
    {
        return Err(GitdCertdChannelError::Authenticate);
    }
    Ok(())
}

fn parse_certificate_verify_response(
    input: &[u8],
    expected_generation: u64,
    expected_scheme: u16,
    expected_request_id: u64,
) -> Result<Vec<u8>, GitdCertdChannelError> {
    let mut cursor = SnapshotCursor { input, offset: 0 };
    if cursor.take(8)? != CERTIFICATE_VERIFY_RESPONSE_MAGIC
        || cursor.u64()? != expected_generation
        || cursor.u16()? != expected_scheme
        || expected_scheme != ECDSA_SECP256R1_SHA256
        || cursor.u64()? != expected_request_id
    {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let signature_length = usize::from(cursor.u16()?);
    if !(8..=MAX_CERTIFICATE_VERIFY_SIGNATURE_BYTES).contains(&signature_length) {
        return Err(GitdCertdChannelError::Authenticate);
    }
    let signature = cursor.take(signature_length)?.to_vec();
    if cursor.offset != input.len() || !valid_ecdsa_der(&signature) {
        return Err(GitdCertdChannelError::Authenticate);
    }
    Ok(signature)
}

fn valid_ecdsa_der(signature: &[u8]) -> bool {
    if signature.len() < 8
        || signature.len() > MAX_CERTIFICATE_VERIFY_SIGNATURE_BYTES
        || signature[0] != 0x30
        || signature[1] & 0x80 != 0
        || usize::from(signature[1]) != signature.len() - 2
    {
        return false;
    }
    let mut offset = 2usize;
    for _ in 0..2 {
        if signature.get(offset) != Some(&0x02) {
            return false;
        }
        let Some(&length) = signature.get(offset + 1) else {
            return false;
        };
        let length = usize::from(length);
        let start = offset + 2;
        let Some(end) = start.checked_add(length) else {
            return false;
        };
        let Some(integer) = signature.get(start..end) else {
            return false;
        };
        if integer.is_empty()
            || integer.len() > 33
            || integer[0] & 0x80 != 0
            || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
            || (integer.len() == 33 && integer[0] != 0)
        {
            return false;
        }
        offset = end;
    }
    offset == signature.len()
}

struct SnapshotCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], GitdCertdChannelError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(GitdCertdChannelError::Authenticate)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(GitdCertdChannelError::Authenticate)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, GitdCertdChannelError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, GitdCertdChannelError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GitdCertdChannelError::Authenticate)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, GitdCertdChannelError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| GitdCertdChannelError::Authenticate)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, GitdCertdChannelError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GitdCertdChannelError::Authenticate)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_certificate::UnixCertdListener;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    fn snapshot_bytes() -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(IDENTITY_SNAPSHOT_MAGIC);
        output.extend_from_slice(&7u64.to_be_bytes());
        output.extend_from_slice(&15u16.to_be_bytes());
        output.extend_from_slice(b"git.example.com");
        output.push(2);
        output.extend_from_slice(&3u32.to_be_bytes());
        output.extend_from_slice(&[0x30, 1, 1]);
        output.extend_from_slice(&3u32.to_be_bytes());
        output.extend_from_slice(&[0x30, 1, 2]);
        output.extend_from_slice(&[3u8; 32]);
        output.extend_from_slice(&100u64.to_be_bytes());
        output.extend_from_slice(&200u64.to_be_bytes());
        output.push(1);
        output.extend_from_slice(&0x0403u16.to_be_bytes());
        output.extend_from_slice(&[4u8; 32]);
        output.push(1);
        output
    }

    #[test]
    fn identity_snapshot_is_exact_hostname_generation_chain_and_policy_bound() {
        let snapshot = parse_identity_snapshot(&snapshot_bytes(), "git.example.com").unwrap();
        assert_eq!(snapshot.identity_generation, 7);
        assert_eq!(snapshot.certificate_chain.len(), 2);
        assert_eq!(snapshot.signature_schemes, [0x0403]);
        assert_eq!(snapshot.publication_digest, [4u8; 32]);
        assert!(parse_identity_snapshot(&snapshot_bytes(), "other.example.com").is_err());
        let mut trailing = snapshot_bytes();
        trailing.push(0);
        assert!(parse_identity_snapshot(&trailing, "git.example.com").is_err());
        let mut rollback = snapshot_bytes();
        rollback[8..16].fill(0);
        assert!(parse_identity_snapshot(&rollback, "git.example.com").is_err());
        assert!(encode_identity_request("Git.example.com").is_err());
    }

    #[test]
    fn certificate_verify_response_binds_generation_scheme_request_and_der() {
        let mut response = Vec::new();
        response.extend_from_slice(CERTIFICATE_VERIFY_RESPONSE_MAGIC);
        response.extend_from_slice(&7u64.to_be_bytes());
        response.extend_from_slice(&ECDSA_SECP256R1_SHA256.to_be_bytes());
        response.extend_from_slice(&11u64.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.extend_from_slice(&[0x30, 6, 2, 1, 1, 2, 1, 1]);
        assert_eq!(
            parse_certificate_verify_response(&response, 7, ECDSA_SECP256R1_SHA256, 11).unwrap(),
            [0x30, 6, 2, 1, 1, 2, 1, 1]
        );
        assert!(
            parse_certificate_verify_response(&response, 8, ECDSA_SECP256R1_SHA256, 11).is_err()
        );
        let mut trailing = response;
        trailing.push(0);
        assert!(
            parse_certificate_verify_response(&trailing, 7, ECDSA_SECP256R1_SHA256, 11).is_err()
        );
        let mut noncanonical = trailing[..trailing.len() - 1].to_vec();
        let signature_offset = 8 + 8 + 2 + 8 + 2;
        noncanonical[signature_offset + 3] = 2;
        assert!(
            parse_certificate_verify_response(&noncanonical, 7, ECDSA_SECP256R1_SHA256, 11)
                .is_err()
        );
    }

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
