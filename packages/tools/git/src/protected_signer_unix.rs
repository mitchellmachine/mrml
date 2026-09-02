//! Authenticated, bounded Unix transport for protected-commit signing use.

use mrml_crypto::hmac_sha256;
use mrml_runtime::{Text, UnixStream, Vector};

use crate::{
    HistoryVerificationError, HybridCommitSignatures, HybridCommitSigningProvider, ObjectFormat,
    ProtectedCommitSigningRequest, SignaturePurpose,
};

const MAGIC: &[u8; 8] = b"MRGPSG01";
const VERSION: u16 = 1;
const OP_SIGN_COMMIT: u16 = 1;
const REQUEST_HEADER: usize = 8 + 2 + 2 + 8 + 8 + 8 + 8 + 32 + 2 + 8;
const RESPONSE_HEADER: usize = 8 + 2 + 2 + 8 + 2 + 2 + 2;
const TAG_BYTES: usize = 32;
const MAX_REPOSITORY_BYTES: usize = 255;
const IO_TIMEOUT_MILLIS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedSignerPeer {
    pub uid: u32,
    pub gid: u32,
}

pub struct ProtectedSignerCapability([u8; 32]);

impl ProtectedSignerCapability {
    pub fn new(bytes: [u8; 32]) -> Result<Self, UnixProtectedSignerError> {
        if bytes == [0; 32] {
            return Err(UnixProtectedSignerError::InvalidCapability);
        }
        Ok(Self(bytes))
    }
}

impl Drop for ProtectedSignerCapability {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixProtectedSignerError {
    InvalidPath,
    InvalidCapability,
    InvalidRequest,
    UnauthorizedPeer,
    Connect,
    Io,
    Protocol,
    Rejected,
    Resource,
}

pub struct UnixProtectedCommitSigningProvider {
    socket: Text,
    expected_peer: ProtectedSignerPeer,
    capability: ProtectedSignerCapability,
    next_request_id: u64,
}

impl UnixProtectedCommitSigningProvider {
    pub fn new(
        socket: &str,
        expected_peer: ProtectedSignerPeer,
        capability: ProtectedSignerCapability,
    ) -> Result<Self, UnixProtectedSignerError> {
        validate_socket_path(socket)?;
        Ok(Self {
            socket: socket.into(),
            expected_peer,
            capability,
            next_request_id: 1,
        })
    }

    fn sign(
        &mut self,
        request: ProtectedCommitSigningRequest<'_>,
    ) -> Result<HybridCommitSignatures, UnixProtectedSignerError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(UnixProtectedSignerError::Resource)?;
        let frame = encode_request(request_id, request, &self.capability)?;
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|_| UnixProtectedSignerError::Connect)?;
        stream
            .set_read_timeout_millis(IO_TIMEOUT_MILLIS)
            .and_then(|_| stream.set_write_timeout_millis(IO_TIMEOUT_MILLIS))
            .map_err(|_| UnixProtectedSignerError::Io)?;
        let peer = stream
            .peer_credentials()
            .map_err(|_| UnixProtectedSignerError::UnauthorizedPeer)?;
        if peer.0 != self.expected_peer.uid || peer.1 != self.expected_peer.gid {
            return Err(UnixProtectedSignerError::UnauthorizedPeer);
        }
        write_frame(&mut stream, &frame)?;
        let response = read_frame(&mut stream)?;
        decode_response(request_id, &response, &self.capability)
    }
}

impl HybridCommitSigningProvider for UnixProtectedCommitSigningProvider {
    fn sign_git_commit(
        &mut self,
        request: ProtectedCommitSigningRequest<'_>,
    ) -> Result<HybridCommitSignatures, HistoryVerificationError> {
        self.sign(request)
            .map_err(|_| HistoryVerificationError::Signature)
    }
}

fn encode_request(
    request_id: u64,
    request: ProtectedCommitSigningRequest<'_>,
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    let repository = request.context.repository.as_str().as_bytes();
    if request_id == 0
        || repository.is_empty()
        || repository.len() > MAX_REPOSITORY_BYTES
        || request.exact_contents.is_empty()
        || request.exact_contents.len() > 16 * 1024 * 1024
        || request.context.object_format != ObjectFormat::Sha256
        || request.context.purpose != SignaturePurpose::GitCommit
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let repository_len =
        u16::try_from(repository.len()).map_err(|_| UnixProtectedSignerError::Resource)?;
    let contents_len = u64::try_from(request.exact_contents.len())
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    let capacity = REQUEST_HEADER
        .checked_add(repository.len())
        .and_then(|value| value.checked_add(request.exact_contents.len()))
        .and_then(|value| value.checked_add(TAG_BYTES))
        .ok_or(UnixProtectedSignerError::Resource)?;
    let mut output: Vector<u8> =
        Vector::with_capacity(capacity).map_err(|_| UnixProtectedSignerError::Resource)?;
    for bytes in [
        MAGIC.as_slice(),
        &VERSION.to_be_bytes(),
        &OP_SIGN_COMMIT.to_be_bytes(),
        &request_id.to_be_bytes(),
        &request.context.repository_generation.0.to_be_bytes(),
        &request.context.trust_generation.0.to_be_bytes(),
        &request.context.revocation_generation.0.to_be_bytes(),
        request.commit.as_bytes(),
        &repository_len.to_be_bytes(),
        &contents_len.to_be_bytes(),
        repository,
        request.exact_contents,
    ] {
        output
            .try_extend_from_slice(bytes)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    }
    let tag = hmac_sha256(&capability.0, &[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

fn decode_response(
    request_id: u64,
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<HybridCommitSignatures, UnixProtectedSignerError> {
    if input.len() < RESPONSE_HEADER + TAG_BYTES || &input[..8] != MAGIC {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = hmac_sha256(&capability.0, &[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..]) {
        return Err(UnixProtectedSignerError::Protocol);
    }
    if read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_SIGN_COMMIT
        || read_u64(input, 12)? != request_id
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let status = read_u16(input, 20)?;
    let openpgp_len = usize::from(read_u16(input, 22)?);
    let ml_dsa_len = usize::from(read_u16(input, 24)?);
    let payload = &input[RESPONSE_HEADER..authenticated_end];
    if status != 0 {
        return Err(UnixProtectedSignerError::Rejected);
    }
    if openpgp_len.checked_add(ml_dsa_len) != Some(payload.len()) {
        return Err(UnixProtectedSignerError::Protocol);
    }
    HybridCommitSignatures::new(&payload[..openpgp_len], &payload[openpgp_len..])
        .map_err(|_| UnixProtectedSignerError::Protocol)
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), UnixProtectedSignerError> {
    let length = u32::try_from(frame.len()).map_err(|_| UnixProtectedSignerError::Resource)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(frame))
        .map_err(|_| UnixProtectedSignerError::Io)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vector<u8>, UnixProtectedSignerError> {
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| UnixProtectedSignerError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    if !(RESPONSE_HEADER + TAG_BYTES
        ..=RESPONSE_HEADER
            + mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES
            + mrml_crypto::ML_DSA_65_SIGNATURE_BYTES
            + TAG_BYTES)
        .contains(&length)
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let mut output =
        Vector::with_capacity(length).map_err(|_| UnixProtectedSignerError::Resource)?;
    output.resize(length, 0);
    stream
        .read_exact(&mut output)
        .map_err(|_| UnixProtectedSignerError::Io)?;
    Ok(output)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, UnixProtectedSignerError> {
    let bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or(UnixProtectedSignerError::Protocol)?
        .try_into()
        .map_err(|_| UnixProtectedSignerError::Protocol)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, UnixProtectedSignerError> {
    let bytes: [u8; 8] = input
        .get(offset..offset + 8)
        .ok_or(UnixProtectedSignerError::Protocol)?
        .try_into()
        .map_err(|_| UnixProtectedSignerError::Protocol)?;
    Ok(u64::from_be_bytes(bytes))
}

fn validate_socket_path(path: &str) -> Result<(), UnixProtectedSignerError> {
    if !path.starts_with('/')
        || path.len() > 107
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(UnixProtectedSignerError::InvalidPath);
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ObjectId, ProtectedHistoryContext, RepositoryGeneration, RepositoryIdentity,
        RevocationGeneration, TrustGeneration,
    };

    #[test]
    fn request_binds_every_context_field_and_capability() {
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        let context = ProtectedHistoryContext {
            repository: &identity,
            repository_generation: RepositoryGeneration(2),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let capability = ProtectedSignerCapability::new([7; 32]).unwrap();
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap();
        let frame = encode_request(
            5,
            ProtectedCommitSigningRequest {
                context,
                commit,
                exact_contents: b"commit bytes",
            },
            &capability,
        )
        .unwrap();
        assert_eq!(&frame[..8], MAGIC);
        assert_eq!(read_u64(&frame, 12).unwrap(), 5);
        assert_eq!(read_u64(&frame, 20).unwrap(), 2);
        assert_eq!(read_u64(&frame, 28).unwrap(), 3);
        assert_eq!(read_u64(&frame, 36).unwrap(), 4);
        let mut altered = frame.clone();
        altered[28] ^= 1;
        let end = altered.len() - TAG_BYTES;
        assert_ne!(
            hmac_sha256(&capability.0, &[&altered[..end]]).as_slice(),
            &altered[end..]
        );
    }

    #[test]
    fn rejects_relative_socket_and_zero_capability() {
        assert_eq!(
            ProtectedSignerCapability::new([0; 32]).err(),
            Some(UnixProtectedSignerError::InvalidCapability)
        );
        let capability = ProtectedSignerCapability::new([1; 32]).unwrap();
        assert_eq!(
            UnixProtectedCommitSigningProvider::new(
                "relative.sock",
                ProtectedSignerPeer { uid: 1, gid: 1 },
                capability,
            )
            .err(),
            Some(UnixProtectedSignerError::InvalidPath)
        );
    }
}
