//! Authenticated, bounded Unix transport for protected-commit signing use.

use mrml_crypto::hmac_sha256;
use mrml_runtime::{Text, UnixStream, Vector};

use crate::{
    HistoryVerificationError, HybridCommitSignatures, HybridCommitSigningProvider, ObjectFormat,
    ObjectId, ProtectedCommitSigningRequest, RepositoryGeneration, RepositoryIdentity,
    RevocationGeneration, SignaturePurpose, TrustGeneration, MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES,
};

const MAGIC: &[u8; 8] = b"MRGPSG02";
const VERSION: u16 = 2;
const OP_SESSION_HELLO: u16 = 0;
const OP_SIGN_COMMIT: u16 = 1;
pub const OP_ADVANCE_GENERATION: u16 = 2;
const SESSION_ID_BYTES: usize = 32;
const SESSION_HELLO_BYTES: usize = 8 + 2 + 2 + SESSION_ID_BYTES + 8 + 8 + 32;
const REQUEST_HEADER: usize =
    8 + 2 + 2 + SESSION_ID_BYTES + 8 + 8 + 8 + 8 + 8 + 8 + 32 + 2 + 8;
const RESPONSE_HEADER: usize = 8 + 2 + 2 + SESSION_ID_BYTES + 8 + 8 + 8 + 2 + 2 + 2;
const ADVANCE_REQUEST_HEADER: usize = 8 + 2 + 2 + SESSION_ID_BYTES + 8 + 8 + 8 + 4;
const TAG_BYTES: usize = 32;
const MAX_REPOSITORY_BYTES: usize = 255;
const MAX_FRAME_BYTES: usize = REQUEST_HEADER + MAX_REPOSITORY_BYTES + 16 * 1024 * 1024 + TAG_BYTES;
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

    fn tag(&self, parts: &[&[u8]]) -> [u8; 32] {
        hmac_sha256(&self.0, parts)
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

pub struct ProtectedSignerRequest {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub session_expires_at: u64,
    pub sequence: u64,
    pub request_id: u64,
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub commit: ObjectId,
    pub exact_contents: Vector<u8>,
}

pub struct ProtectedSignerAdvanceRequest {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub session_expires_at: u64,
    pub sequence: u64,
    pub request_id: u64,
    pub authenticated_receipt: Vector<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedSignerSession {
    pub id: [u8; SESSION_ID_BYTES],
    pub expires_at: u64,
    pub maximum_sequence: u64,
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
        let hello = read_frame(&mut stream).map_err(|error| {
            mrml_runtime::mrml_eprintln!(
                "component=mrml-git event=protected_signer_request_failed stage=hello_read category={error:?}"
            );
            error
        })?;
        let session = decode_protected_signer_hello(&hello, &self.capability).map_err(|error| {
            mrml_runtime::mrml_eprintln!(
                "component=mrml-git event=protected_signer_request_failed stage=hello_authentication category={error:?}"
            );
            error
        })?;
        let now = mrml_runtime::unix_time_seconds().ok_or_else(|| {
            mrml_runtime::mrml_eprintln!(
                "component=mrml-git event=protected_signer_request_failed stage=trusted_time category=Protocol"
            );
            UnixProtectedSignerError::Protocol
        })?;
        if session.expires_at < now || session.maximum_sequence == 0 {
            mrml_runtime::mrml_eprintln!(
                "component=mrml-git event=protected_signer_request_failed stage=session_policy category=Protocol"
            );
            return Err(UnixProtectedSignerError::Protocol);
        }
        let frame = encode_request(request_id, session, 1, request, &self.capability)?;
        write_frame(&mut stream, &frame)?;
        let response = read_frame(&mut stream)?;
        decode_response(request_id, session, 1, &response, &self.capability)
    }
}

impl HybridCommitSigningProvider for UnixProtectedCommitSigningProvider {
    fn sign_git_commit(
        &mut self,
        request: ProtectedCommitSigningRequest<'_>,
    ) -> Result<HybridCommitSignatures, HistoryVerificationError> {
        self.sign(request).map_err(|error| {
            mrml_runtime::mrml_eprintln!(
                "component=mrml-git event=protected_signer_request_failed category={error:?}"
            );
            HistoryVerificationError::Signature
        })
    }
}

impl crate::ProtectedSignerGenerationAdvancer for UnixProtectedCommitSigningProvider {
    fn advance_repository_generation(
        &mut self,
        authenticated_receipt: &[u8],
    ) -> Result<(), HistoryVerificationError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(HistoryVerificationError::Signature)?;
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|_| HistoryVerificationError::Signature)?;
        stream
            .set_read_timeout_millis(IO_TIMEOUT_MILLIS)
            .and_then(|_| stream.set_write_timeout_millis(IO_TIMEOUT_MILLIS))
            .map_err(|_| HistoryVerificationError::Signature)?;
        let peer = stream
            .peer_credentials()
            .map_err(|_| HistoryVerificationError::Signature)?;
        if peer.0 != self.expected_peer.uid || peer.1 != self.expected_peer.gid {
            return Err(HistoryVerificationError::Signature);
        }
        let hello = read_frame(&mut stream).map_err(|_| HistoryVerificationError::Signature)?;
        let session = decode_protected_signer_hello(&hello, &self.capability)
            .map_err(|_| HistoryVerificationError::Signature)?;
        let now = mrml_runtime::unix_time_seconds().ok_or(HistoryVerificationError::Signature)?;
        if session.expires_at < now || session.maximum_sequence == 0 {
            return Err(HistoryVerificationError::Signature);
        }
        let frame = encode_advance_request(
            request_id,
            session,
            1,
            authenticated_receipt,
            &self.capability,
        )
        .map_err(|_| HistoryVerificationError::Signature)?;
        write_frame(&mut stream, &frame).map_err(|_| HistoryVerificationError::Signature)?;
        let response = read_frame(&mut stream).map_err(|_| HistoryVerificationError::Signature)?;
        decode_advance_response(request_id, session, 1, &response, &self.capability)
            .map_err(|_| HistoryVerificationError::Signature)
    }
}

fn encode_request(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    request: ProtectedCommitSigningRequest<'_>,
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    let repository = request.context.repository.as_str().as_bytes();
    if request_id == 0
        || session.id == [0; SESSION_ID_BYTES]
        || session.expires_at == 0
        || sequence == 0
        || sequence > session.maximum_sequence
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
        &session.id,
        &session.expires_at.to_be_bytes(),
        &sequence.to_be_bytes(),
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
    let tag = capability.tag(&[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

pub fn encode_advance_request(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    authenticated_receipt: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    if request_id == 0
        || session.id == [0; SESSION_ID_BYTES]
        || sequence == 0
        || sequence > session.maximum_sequence
        || authenticated_receipt.is_empty()
        || authenticated_receipt.len() > MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let length = u32::try_from(authenticated_receipt.len())
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    let mut output = Vector::with_capacity(
        ADVANCE_REQUEST_HEADER + authenticated_receipt.len() + TAG_BYTES,
    )
    .map_err(|_| UnixProtectedSignerError::Resource)?;
    for bytes in [
        MAGIC.as_slice(),
        &VERSION.to_be_bytes(),
        &OP_ADVANCE_GENERATION.to_be_bytes(),
        &session.id,
        &session.expires_at.to_be_bytes(),
        &sequence.to_be_bytes(),
        &request_id.to_be_bytes(),
        &length.to_be_bytes(),
        authenticated_receipt,
    ] {
        output
            .try_extend_from_slice(bytes)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    }
    let tag = capability.tag(&[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

pub fn decode_advance_request(
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<ProtectedSignerAdvanceRequest, UnixProtectedSignerError> {
    if input.len() < ADVANCE_REQUEST_HEADER + 1 + TAG_BYTES
        || input.len() > ADVANCE_REQUEST_HEADER + MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES + TAG_BYTES
        || &input[..8] != MAGIC
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = capability.tag(&[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..])
        || read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_ADVANCE_GENERATION
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let mut session_id = [0; SESSION_ID_BYTES];
    session_id.copy_from_slice(input.get(12..44).ok_or(UnixProtectedSignerError::Protocol)?);
    let length = usize::try_from(read_u32(input, 68)?)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    if session_id == [0; SESSION_ID_BYTES]
        || read_u64(input, 44)? == 0
        || read_u64(input, 52)? == 0
        || read_u64(input, 60)? == 0
        || length == 0
        || length > MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES
        || ADVANCE_REQUEST_HEADER.checked_add(length) != Some(authenticated_end)
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let mut receipt = Vector::new();
    receipt
        .try_extend_from_slice(&input[ADVANCE_REQUEST_HEADER..authenticated_end])
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(ProtectedSignerAdvanceRequest {
        session_id,
        session_expires_at: read_u64(input, 44)?,
        sequence: read_u64(input, 52)?,
        request_id: read_u64(input, 60)?,
        authenticated_receipt: receipt,
    })
}

pub fn encode_protected_signer_hello(
    session: ProtectedSignerSession,
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    if session.id == [0; SESSION_ID_BYTES]
        || session.expires_at == 0
        || session.maximum_sequence == 0
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let mut output = Vector::with_capacity(SESSION_HELLO_BYTES)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    for bytes in [
        MAGIC.as_slice(),
        &VERSION.to_be_bytes(),
        &OP_SESSION_HELLO.to_be_bytes(),
        &session.id,
        &session.expires_at.to_be_bytes(),
        &session.maximum_sequence.to_be_bytes(),
    ] {
        output
            .try_extend_from_slice(bytes)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    }
    let tag = capability.tag(&[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

pub fn decode_protected_signer_hello(
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<ProtectedSignerSession, UnixProtectedSignerError> {
    if input.len() != SESSION_HELLO_BYTES
        || &input[..8] != MAGIC
        || read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_SESSION_HELLO
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = capability.tag(&[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..]) {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let mut id = [0; SESSION_ID_BYTES];
    id.copy_from_slice(&input[12..44]);
    let session = ProtectedSignerSession {
        id,
        expires_at: read_u64(input, 44)?,
        maximum_sequence: read_u64(input, 52)?,
    };
    if session.id == [0; SESSION_ID_BYTES]
        || session.expires_at == 0
        || session.maximum_sequence == 0
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    Ok(session)
}

pub fn decode_protected_signer_request(
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<ProtectedSignerRequest, UnixProtectedSignerError> {
    if input.len() < REQUEST_HEADER + TAG_BYTES
        || input.len() > MAX_FRAME_BYTES
        || &input[..8] != MAGIC
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = capability.tag(&[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..])
        || read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_SIGN_COMMIT
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let mut session_id = [0; SESSION_ID_BYTES];
    session_id.copy_from_slice(input.get(12..44).ok_or(UnixProtectedSignerError::Protocol)?);
    let session_expires_at = read_u64(input, 44)?;
    let sequence = read_u64(input, 52)?;
    let request_id = read_u64(input, 60)?;
    let repository_generation = RepositoryGeneration(read_u64(input, 68)?);
    let trust_generation = TrustGeneration(read_u64(input, 76)?);
    let revocation_generation = RevocationGeneration(read_u64(input, 84)?);
    let commit = ObjectId::from_bytes(
        ObjectFormat::Sha256,
        input
            .get(92..124)
            .ok_or(UnixProtectedSignerError::Protocol)?,
    )
    .ok_or(UnixProtectedSignerError::Protocol)?;
    let repository_len = usize::from(read_u16(input, 124)?);
    let contents_len =
        usize::try_from(read_u64(input, 126)?).map_err(|_| UnixProtectedSignerError::Resource)?;
    let payload_end = REQUEST_HEADER
        .checked_add(repository_len)
        .and_then(|value| value.checked_add(contents_len))
        .ok_or(UnixProtectedSignerError::Resource)?;
    if session_id == [0; SESSION_ID_BYTES]
        || session_expires_at == 0
        || sequence == 0
        || request_id == 0
        || repository_generation.0 == 0
        || trust_generation.0 == 0
        || revocation_generation.0 == 0
        || commit.is_zero()
        || repository_len == 0
        || repository_len > MAX_REPOSITORY_BYTES
        || contents_len == 0
        || contents_len > 16 * 1024 * 1024
        || payload_end != authenticated_end
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let repository_end = REQUEST_HEADER + repository_len;
    let repository_text = core::str::from_utf8(&input[REQUEST_HEADER..repository_end])
        .map_err(|_| UnixProtectedSignerError::InvalidRequest)?;
    let repository = RepositoryIdentity::parse(repository_text)
        .map_err(|_| UnixProtectedSignerError::InvalidRequest)?;
    let mut exact_contents =
        Vector::with_capacity(contents_len).map_err(|_| UnixProtectedSignerError::Resource)?;
    exact_contents
        .try_extend_from_slice(&input[repository_end..payload_end])
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(ProtectedSignerRequest {
        session_id,
        session_expires_at,
        sequence,
        request_id,
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        commit,
        exact_contents,
    })
}

pub fn protected_signer_operation(input: &[u8]) -> Result<u16, UnixProtectedSignerError> {
    if input.len() < 12 || &input[..8] != MAGIC || read_u16(input, 8)? != VERSION {
        return Err(UnixProtectedSignerError::Protocol);
    }
    match read_u16(input, 10)? {
        OP_SIGN_COMMIT => Ok(OP_SIGN_COMMIT),
        OP_ADVANCE_GENERATION => Ok(OP_ADVANCE_GENERATION),
        _ => Err(UnixProtectedSignerError::Protocol),
    }
}

pub fn encode_protected_signer_response(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    result: Result<&HybridCommitSignatures, UnixProtectedSignerError>,
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    if request_id == 0
        || session.id == [0; SESSION_ID_BYTES]
        || sequence == 0
        || sequence > session.maximum_sequence
    {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let (status, openpgp, ml_dsa) = match result {
        Ok(signatures) => (0u16, signatures.openpgp(), signatures.ml_dsa()),
        Err(_) => (1u16, &[][..], &[][..]),
    };
    let openpgp_len =
        u16::try_from(openpgp.len()).map_err(|_| UnixProtectedSignerError::Resource)?;
    let ml_dsa_len = u16::try_from(ml_dsa.len()).map_err(|_| UnixProtectedSignerError::Resource)?;
    let mut output =
        Vector::with_capacity(RESPONSE_HEADER + openpgp.len() + ml_dsa.len() + TAG_BYTES)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    for bytes in [
        MAGIC.as_slice(),
        &VERSION.to_be_bytes(),
        &OP_SIGN_COMMIT.to_be_bytes(),
        &session.id,
        &session.expires_at.to_be_bytes(),
        &sequence.to_be_bytes(),
        &request_id.to_be_bytes(),
        &status.to_be_bytes(),
        &openpgp_len.to_be_bytes(),
        &ml_dsa_len.to_be_bytes(),
        openpgp,
        ml_dsa,
    ] {
        output
            .try_extend_from_slice(bytes)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    }
    let tag = capability.tag(&[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

pub fn encode_advance_response(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    accepted: bool,
    capability: &ProtectedSignerCapability,
) -> Result<Vector<u8>, UnixProtectedSignerError> {
    if request_id == 0 || session.id == [0; SESSION_ID_BYTES] || sequence == 0 {
        return Err(UnixProtectedSignerError::InvalidRequest);
    }
    let status = if accepted { 0u16 } else { 1u16 };
    let mut output = Vector::with_capacity(RESPONSE_HEADER + TAG_BYTES)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    for bytes in [
        MAGIC.as_slice(),
        &VERSION.to_be_bytes(),
        &OP_ADVANCE_GENERATION.to_be_bytes(),
        &session.id,
        &session.expires_at.to_be_bytes(),
        &sequence.to_be_bytes(),
        &request_id.to_be_bytes(),
        &status.to_be_bytes(),
        &0u16.to_be_bytes(),
        &0u16.to_be_bytes(),
    ] {
        output
            .try_extend_from_slice(bytes)
            .map_err(|_| UnixProtectedSignerError::Resource)?;
    }
    let tag = capability.tag(&[&output]);
    output
        .try_extend_from_slice(&tag)
        .map_err(|_| UnixProtectedSignerError::Resource)?;
    Ok(output)
}

fn decode_advance_response(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<(), UnixProtectedSignerError> {
    if input.len() != RESPONSE_HEADER + TAG_BYTES || &input[..8] != MAGIC {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = capability.tag(&[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..])
        || read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_ADVANCE_GENERATION
        || input.get(12..44) != Some(session.id.as_slice())
        || read_u64(input, 44)? != session.expires_at
        || read_u64(input, 52)? != sequence
        || read_u64(input, 60)? != request_id
        || read_u16(input, 70)? != 0
        || read_u16(input, 72)? != 0
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    match read_u16(input, 68)? {
        0 => Ok(()),
        1 => Err(UnixProtectedSignerError::Rejected),
        _ => Err(UnixProtectedSignerError::Protocol),
    }
}

fn decode_response(
    request_id: u64,
    session: ProtectedSignerSession,
    sequence: u64,
    input: &[u8],
    capability: &ProtectedSignerCapability,
) -> Result<HybridCommitSignatures, UnixProtectedSignerError> {
    if input.len() < RESPONSE_HEADER + TAG_BYTES || &input[..8] != MAGIC {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let authenticated_end = input.len() - TAG_BYTES;
    let expected = capability.tag(&[&input[..authenticated_end]]);
    if !constant_time_equal(&expected, &input[authenticated_end..]) {
        return Err(UnixProtectedSignerError::Protocol);
    }
    if read_u16(input, 8)? != VERSION
        || read_u16(input, 10)? != OP_SIGN_COMMIT
        || input.get(12..44) != Some(session.id.as_slice())
        || read_u64(input, 44)? != session.expires_at
        || read_u64(input, 52)? != sequence
        || read_u64(input, 60)? != request_id
    {
        return Err(UnixProtectedSignerError::Protocol);
    }
    let status = read_u16(input, 68)?;
    let openpgp_len = usize::from(read_u16(input, 70)?);
    let ml_dsa_len = usize::from(read_u16(input, 72)?);
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
    if !valid_inbound_frame_length(length) {
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

fn valid_inbound_frame_length(length: usize) -> bool {
    length == SESSION_HELLO_BYTES
        || (RESPONSE_HEADER + TAG_BYTES
            ..=RESPONSE_HEADER
                + mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES
                + mrml_crypto::ML_DSA_65_SIGNATURE_BYTES
                + TAG_BYTES)
            .contains(&length)
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

fn read_u32(input: &[u8], offset: usize) -> Result<u32, UnixProtectedSignerError> {
    Ok(u32::from_be_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(UnixProtectedSignerError::Protocol)?
            .try_into()
            .map_err(|_| UnixProtectedSignerError::Protocol)?,
    ))
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
        let session = ProtectedSignerSession {
            id: [6; 32],
            expires_at: 10,
            maximum_sequence: 1,
        };
        let frame = encode_request(
            5,
            session,
            1,
            ProtectedCommitSigningRequest {
                context,
                commit,
                exact_contents: b"commit bytes",
            },
            &capability,
        )
        .unwrap();
        let decoded = decode_protected_signer_request(&frame, &capability).unwrap();
        assert_eq!(decoded.request_id, 5);
        assert_eq!(decoded.session_id, session.id);
        assert_eq!(decoded.session_expires_at, session.expires_at);
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.repository, identity);
        assert_eq!(decoded.commit, commit);
        assert_eq!(&*decoded.exact_contents, b"commit bytes");
        assert_eq!(&frame[..8], MAGIC);
        assert_eq!(read_u64(&frame, 60).unwrap(), 5);
        assert_eq!(read_u64(&frame, 68).unwrap(), 2);
        assert_eq!(read_u64(&frame, 76).unwrap(), 3);
        assert_eq!(read_u64(&frame, 84).unwrap(), 4);
        let mut altered = frame.clone();
        altered[76] ^= 1;
        let end = altered.len() - TAG_BYTES;
        assert_ne!(
            hmac_sha256(&capability.0, &[&altered[..end]]).as_slice(),
            &altered[end..]
        );
        let wrong_capability = ProtectedSignerCapability::new([8; 32]).unwrap();
        assert_eq!(
            decode_protected_signer_request(&frame, &wrong_capability).err(),
            Some(UnixProtectedSignerError::Protocol)
        );
    }

    #[test]
    fn response_is_authenticated_bounded_and_exactly_framed() {
        let capability = ProtectedSignerCapability::new([7; 32]).unwrap();
        let signatures =
            HybridCommitSignatures::new(&[3; 64], &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES])
                .unwrap();
        let session = ProtectedSignerSession {
            id: [8; 32],
            expires_at: 10,
            maximum_sequence: 1,
        };
        let response =
            encode_protected_signer_response(9, session, 1, Ok(&signatures), &capability).unwrap();
        let decoded = decode_response(9, session, 1, &response, &capability).unwrap();
        assert_eq!(decoded.openpgp(), &[3; 64]);
        assert_eq!(
            decoded.ml_dsa(),
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES]
        );
        let mut tampered = response;
        tampered[68] ^= 1;
        assert_eq!(
            decode_response(9, session, 1, &tampered, &capability).err(),
            Some(UnixProtectedSignerError::Protocol)
        );
    }

    #[test]
    fn inbound_frame_bounds_admit_session_hello_and_bounded_responses() {
        let minimum_response = RESPONSE_HEADER + TAG_BYTES;
        let maximum_response = RESPONSE_HEADER
            + mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES
            + mrml_crypto::ML_DSA_65_SIGNATURE_BYTES
            + TAG_BYTES;
        assert!(valid_inbound_frame_length(SESSION_HELLO_BYTES));
        assert!(valid_inbound_frame_length(minimum_response));
        assert!(valid_inbound_frame_length(maximum_response));
        assert!(!valid_inbound_frame_length(0));
        assert!(!valid_inbound_frame_length(SESSION_HELLO_BYTES - 1));
        assert!(!valid_inbound_frame_length(maximum_response + 1));
    }

    #[test]
    fn generation_advance_frames_are_operation_and_capability_bound() {
        let capability = ProtectedSignerCapability::new([7; 32]).unwrap();
        let session = ProtectedSignerSession {
            id: [8; 32],
            expires_at: 10,
            maximum_sequence: 1,
        };
        let receipt = [0x31; 137];
        let request = encode_advance_request(11, session, 1, &receipt, &capability).unwrap();
        assert_eq!(protected_signer_operation(&request), Ok(OP_ADVANCE_GENERATION));
        let decoded = decode_advance_request(&request, &capability).unwrap();
        assert_eq!(decoded.request_id, 11);
        assert_eq!(&decoded.authenticated_receipt[..], &receipt);
        let response = encode_advance_response(11, session, 1, true, &capability).unwrap();
        assert_eq!(
            decode_advance_response(11, session, 1, &response, &capability),
            Ok(())
        );
        let mut tampered = request;
        tampered[72] ^= 1;
        assert_eq!(
            decode_advance_request(&tampered, &capability).err(),
            Some(UnixProtectedSignerError::Protocol)
        );
    }

    #[test]
    fn session_hello_is_authenticated_and_replay_context_is_exact() {
        let capability = ProtectedSignerCapability::new([7; 32]).unwrap();
        let session = ProtectedSignerSession {
            id: [5; 32],
            expires_at: 44,
            maximum_sequence: 1,
        };
        let hello = encode_protected_signer_hello(session, &capability).unwrap();
        assert_eq!(decode_protected_signer_hello(&hello, &capability).unwrap(), session);
        let mut tampered = hello;
        tampered[12] ^= 1;
        assert_eq!(
            decode_protected_signer_hello(&tampered, &capability).err(),
            Some(UnixProtectedSignerError::Protocol)
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
