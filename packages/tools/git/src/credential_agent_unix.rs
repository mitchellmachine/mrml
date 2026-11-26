//! Authenticated, scope-bound Unix transport for HTTPS credentials.

use mrml_crypto::hmac_sha256;
use mrml_runtime::{Text, UnixStream, Vector};

use crate::{
    HttpsCredentialAction, HttpsCredentialError, HttpsCredentialProvider, HttpsCredentialScope,
    ScopedBearerCredential,
};

const MAGIC: &[u8; 8] = b"MRGCRA01";
const VERSION: u16 = 1;
const HELLO_BYTES: usize = 8 + 2 + 32 + 8 + 32;
const REQUEST_FIXED_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 8 + 2 + 1 + 2 + 2;
const RESPONSE_FIXED_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 8 + 1 + 2;
const TAG_BYTES: usize = 32;
const TOKEN_BYTES: usize = 64;
const MAX_HOST_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 1024;
const MAX_FRAME_BYTES: usize = REQUEST_FIXED_BYTES + MAX_HOST_BYTES + MAX_PATH_BYTES + TAG_BYTES;
const IO_TIMEOUT_MILLIS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialAgentPeer {
    pub uid: u32,
    pub gid: u32,
}

pub struct CredentialAgentCapability([u8; 32]);

impl CredentialAgentCapability {
    pub fn new(bytes: [u8; 32]) -> Result<Self, CredentialAgentError> {
        if bytes == [0; 32] {
            return Err(CredentialAgentError::InvalidCapability);
        }
        Ok(Self(bytes))
    }

    fn tag(&self, parts: &[&[u8]]) -> [u8; 32] {
        hmac_sha256(&self.0, parts)
    }
}

impl Drop for CredentialAgentCapability {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAgentError {
    InvalidPath,
    InvalidCapability,
    InvalidFrame,
    UnauthorizedPeer,
    Connect,
    Io,
    Expired,
    Denied,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialAgentSession {
    pub id: [u8; 32],
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAgentRequest {
    pub session: CredentialAgentSession,
    pub request_id: u64,
    pub credential_generation: u64,
    pub scope: HttpsCredentialScope,
}

pub struct UnixHttpsCredentialProvider {
    socket: Text,
    expected_peer: CredentialAgentPeer,
    capability: CredentialAgentCapability,
    credential_generation: u64,
    next_request_id: u64,
}

impl UnixHttpsCredentialProvider {
    pub fn new(
        socket: &str,
        expected_peer: CredentialAgentPeer,
        capability: CredentialAgentCapability,
        credential_generation: u64,
    ) -> Result<Self, CredentialAgentError> {
        if !socket.starts_with('/')
            || socket.len() > 107
            || socket.as_bytes().contains(&0)
            || socket.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(CredentialAgentError::InvalidPath);
        }
        if expected_peer.uid == 0 || expected_peer.gid == 0 || credential_generation == 0 {
            return Err(CredentialAgentError::InvalidFrame);
        }
        Ok(Self {
            socket: socket.into(),
            expected_peer,
            capability,
            credential_generation,
            next_request_id: 1,
        })
    }
}

impl HttpsCredentialProvider for UnixHttpsCredentialProvider {
    fn credential(
        &mut self,
        scope: &HttpsCredentialScope,
    ) -> Result<ScopedBearerCredential, HttpsCredentialError> {
        let result = self.request(scope);
        result.map_err(|error| match error {
            CredentialAgentError::Denied | CredentialAgentError::Expired => {
                HttpsCredentialError::Denied
            }
            CredentialAgentError::Resource => HttpsCredentialError::Resource,
            _ => HttpsCredentialError::Unavailable,
        })
    }
}

impl UnixHttpsCredentialProvider {
    fn request(
        &mut self,
        scope: &HttpsCredentialScope,
    ) -> Result<ScopedBearerCredential, CredentialAgentError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(CredentialAgentError::Resource)?;
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|_| CredentialAgentError::Connect)?;
        stream
            .set_read_timeout_millis(IO_TIMEOUT_MILLIS)
            .and_then(|_| stream.set_write_timeout_millis(IO_TIMEOUT_MILLIS))
            .map_err(|_| CredentialAgentError::Io)?;
        let peer = stream
            .peer_credentials()
            .map_err(|_| CredentialAgentError::UnauthorizedPeer)?;
        if peer != (self.expected_peer.uid, self.expected_peer.gid) {
            return Err(CredentialAgentError::UnauthorizedPeer);
        }
        let hello = read_frame(&mut stream)?;
        let session = decode_credential_agent_hello(&hello, &self.capability)?;
        let now = mrml_runtime::unix_time_seconds().ok_or(CredentialAgentError::Expired)?;
        if session.expires_at < now {
            return Err(CredentialAgentError::Expired);
        }
        let request = encode_credential_agent_request(
            session,
            request_id,
            self.credential_generation,
            scope,
            &self.capability,
        )?;
        write_frame(&mut stream, &request)?;
        let mut response = read_frame(&mut stream)?;
        let result = decode_credential_agent_response(
            &response,
            session,
            request_id,
            self.credential_generation,
            scope,
            &self.capability,
            now,
        );
        erase(&mut response);
        result
    }
}

pub fn encode_credential_agent_hello(
    session: CredentialAgentSession,
    capability: &CredentialAgentCapability,
) -> Result<Vector<u8>, CredentialAgentError> {
    if session.id == [0; 32] || session.expires_at == 0 {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let mut frame = Vector::new();
    extend(&mut frame, MAGIC)?;
    extend(&mut frame, &VERSION.to_be_bytes())?;
    extend(&mut frame, &session.id)?;
    extend(&mut frame, &session.expires_at.to_be_bytes())?;
    let tag = capability.tag(&[b"mrml-git-credential-agent-hello-v1", &frame]);
    extend(&mut frame, &tag)?;
    Ok(frame)
}

pub fn decode_credential_agent_hello(
    frame: &[u8],
    capability: &CredentialAgentCapability,
) -> Result<CredentialAgentSession, CredentialAgentError> {
    if frame.len() != HELLO_BYTES || &frame[..8] != MAGIC || read_u16(frame, 8)? != VERSION {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let authenticated = HELLO_BYTES - TAG_BYTES;
    let expected = capability.tag(&[
        b"mrml-git-credential-agent-hello-v1",
        &frame[..authenticated],
    ]);
    if !constant_time_equal(&expected, &frame[authenticated..]) {
        return Err(CredentialAgentError::InvalidCapability);
    }
    let mut id = [0; 32];
    id.copy_from_slice(&frame[10..42]);
    let session = CredentialAgentSession {
        id,
        expires_at: read_u64(frame, 42)?,
    };
    if session.id == [0; 32] || session.expires_at == 0 {
        return Err(CredentialAgentError::InvalidFrame);
    }
    Ok(session)
}

pub fn encode_credential_agent_request(
    session: CredentialAgentSession,
    request_id: u64,
    credential_generation: u64,
    scope: &HttpsCredentialScope,
    capability: &CredentialAgentCapability,
) -> Result<Vector<u8>, CredentialAgentError> {
    if request_id == 0 || credential_generation == 0 {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let host = scope.host.as_bytes();
    let path = scope.repository_path.as_bytes();
    let host_len = u16::try_from(host.len()).map_err(|_| CredentialAgentError::Resource)?;
    let path_len = u16::try_from(path.len()).map_err(|_| CredentialAgentError::Resource)?;
    let mut frame = Vector::new();
    extend(&mut frame, MAGIC)?;
    extend(&mut frame, &VERSION.to_be_bytes())?;
    extend(&mut frame, &session.id)?;
    extend(&mut frame, &session.expires_at.to_be_bytes())?;
    extend(&mut frame, &request_id.to_be_bytes())?;
    extend(&mut frame, &credential_generation.to_be_bytes())?;
    extend(&mut frame, &scope.port.to_be_bytes())?;
    frame.push(match scope.action {
        HttpsCredentialAction::Read => 1,
        HttpsCredentialAction::Write => 2,
    });
    extend(&mut frame, &host_len.to_be_bytes())?;
    extend(&mut frame, &path_len.to_be_bytes())?;
    extend(&mut frame, host)?;
    extend(&mut frame, path)?;
    let tag = capability.tag(&[b"mrml-git-credential-agent-request-v1", &frame]);
    extend(&mut frame, &tag)?;
    Ok(frame)
}

pub fn decode_credential_agent_request(
    frame: &[u8],
    expected_session: CredentialAgentSession,
    capability: &CredentialAgentCapability,
) -> Result<CredentialAgentRequest, CredentialAgentError> {
    if frame.len() < REQUEST_FIXED_BYTES + TAG_BYTES
        || frame.len() > MAX_FRAME_BYTES
        || &frame[..8] != MAGIC
        || read_u16(frame, 8)? != VERSION
    {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let authenticated = frame.len() - TAG_BYTES;
    let expected = capability.tag(&[
        b"mrml-git-credential-agent-request-v1",
        &frame[..authenticated],
    ]);
    if !constant_time_equal(&expected, &frame[authenticated..]) {
        return Err(CredentialAgentError::InvalidCapability);
    }
    if frame[10..42] != expected_session.id || read_u64(frame, 42)? != expected_session.expires_at {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let request_id = read_u64(frame, 50)?;
    let credential_generation = read_u64(frame, 58)?;
    let port = read_u16(frame, 66)?;
    let action = match frame[68] {
        1 => HttpsCredentialAction::Read,
        2 => HttpsCredentialAction::Write,
        _ => return Err(CredentialAgentError::InvalidFrame),
    };
    let host_len = usize::from(read_u16(frame, 69)?);
    let path_len = usize::from(read_u16(frame, 71)?);
    if request_id == 0
        || credential_generation == 0
        || host_len == 0
        || host_len > MAX_HOST_BYTES
        || path_len == 0
        || path_len > MAX_PATH_BYTES
        || 73usize
            .checked_add(host_len)
            .and_then(|v| v.checked_add(path_len))
            != Some(authenticated)
    {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let host = core::str::from_utf8(&frame[73..73 + host_len])
        .map_err(|_| CredentialAgentError::InvalidFrame)?;
    let path = core::str::from_utf8(&frame[73 + host_len..authenticated])
        .map_err(|_| CredentialAgentError::InvalidFrame)?;
    let scope = HttpsCredentialScope::new(host, port, path, action)
        .map_err(|_| CredentialAgentError::InvalidFrame)?;
    Ok(CredentialAgentRequest {
        session: expected_session,
        request_id,
        credential_generation,
        scope,
    })
}

pub fn encode_credential_agent_response(
    request: &CredentialAgentRequest,
    expires_at: u64,
    encoded_token: Option<&[u8]>,
    capability: &CredentialAgentCapability,
) -> Result<Vector<u8>, CredentialAgentError> {
    if expires_at == 0 || encoded_token.is_some_and(|token| token.len() != TOKEN_BYTES) {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let mut frame = Vector::new();
    extend(&mut frame, MAGIC)?;
    extend(&mut frame, &VERSION.to_be_bytes())?;
    extend(&mut frame, &request.session.id)?;
    extend(&mut frame, &request.request_id.to_be_bytes())?;
    extend(&mut frame, &request.credential_generation.to_be_bytes())?;
    extend(&mut frame, &expires_at.to_be_bytes())?;
    frame.push(u8::from(encoded_token.is_some()));
    extend(
        &mut frame,
        &(encoded_token.map_or(0, <[u8]>::len) as u16).to_be_bytes(),
    )?;
    if let Some(token) = encoded_token {
        extend(&mut frame, token)?;
    }
    let tag = capability.tag(&[b"mrml-git-credential-agent-response-v1", &frame]);
    extend(&mut frame, &tag)?;
    Ok(frame)
}

#[allow(clippy::too_many_arguments)]
fn decode_credential_agent_response(
    frame: &[u8],
    session: CredentialAgentSession,
    request_id: u64,
    credential_generation: u64,
    scope: &HttpsCredentialScope,
    capability: &CredentialAgentCapability,
    now: u64,
) -> Result<ScopedBearerCredential, CredentialAgentError> {
    if frame.len() < RESPONSE_FIXED_BYTES + TAG_BYTES
        || &frame[..8] != MAGIC
        || read_u16(frame, 8)? != VERSION
    {
        return Err(CredentialAgentError::InvalidFrame);
    }
    let authenticated = frame.len() - TAG_BYTES;
    let expected = capability.tag(&[
        b"mrml-git-credential-agent-response-v1",
        &frame[..authenticated],
    ]);
    if !constant_time_equal(&expected, &frame[authenticated..]) {
        return Err(CredentialAgentError::InvalidCapability);
    }
    let token_len = usize::from(read_u16(frame, 67)?);
    if frame[10..42] != session.id
        || read_u64(frame, 42)? != request_id
        || read_u64(frame, 50)? != credential_generation
        || read_u64(frame, 58)? < now
        || 69usize.checked_add(token_len) != Some(authenticated)
    {
        return Err(CredentialAgentError::InvalidFrame);
    }
    match (frame[66], token_len) {
        (0, 0) => Err(CredentialAgentError::Denied),
        (1, TOKEN_BYTES) => {
            ScopedBearerCredential::from_provider_token(scope.clone(), &frame[69..authenticated])
                .map_err(|_| CredentialAgentError::InvalidFrame)
        }
        _ => Err(CredentialAgentError::InvalidFrame),
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vector<u8>, CredentialAgentError> {
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| CredentialAgentError::Io)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| CredentialAgentError::Resource)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(CredentialAgentError::Resource);
    }
    let mut frame = Vector::with_capacity(length).map_err(|_| CredentialAgentError::Resource)?;
    frame.resize(length, 0);
    stream
        .read_exact(&mut frame)
        .map_err(|_| CredentialAgentError::Io)?;
    Ok(frame)
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), CredentialAgentError> {
    let length = u32::try_from(frame.len()).map_err(|_| CredentialAgentError::Resource)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(frame))
        .map_err(|_| CredentialAgentError::Io)
}

fn extend(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), CredentialAgentError> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| CredentialAgentError::Resource)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, CredentialAgentError> {
    input
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(CredentialAgentError::InvalidFrame)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, CredentialAgentError> {
    input
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(CredentialAgentError::InvalidFrame)
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

fn erase(bytes: &mut [u8]) {
    mrml_crypto::erase_secret_bytes(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_bind_session_scope_generation_and_capability() {
        let capability = CredentialAgentCapability::new([7; 32]).unwrap();
        let session = CredentialAgentSession {
            id: [9; 32],
            expires_at: 500,
        };
        let scope = HttpsCredentialScope::new(
            "git.example",
            443,
            "/owner/repo.git",
            HttpsCredentialAction::Write,
        )
        .unwrap();
        let hello = encode_credential_agent_hello(session, &capability).unwrap();
        assert_eq!(
            decode_credential_agent_hello(&hello, &capability).unwrap(),
            session
        );
        let frame = encode_credential_agent_request(session, 4, 8, &scope, &capability).unwrap();
        let request = decode_credential_agent_request(&frame, session, &capability).unwrap();
        assert_eq!(request.scope, scope);
        let response =
            encode_credential_agent_response(&request, 499, Some(&[b'a'; 64]), &capability)
                .unwrap();
        assert!(
            decode_credential_agent_response(&response, session, 4, 8, &scope, &capability, 498)
                .is_ok()
        );
    }

    #[test]
    fn tamper_wrong_scope_generation_and_expiry_fail_closed() {
        let capability = CredentialAgentCapability::new([7; 32]).unwrap();
        let wrong = CredentialAgentCapability::new([8; 32]).unwrap();
        let session = CredentialAgentSession {
            id: [9; 32],
            expires_at: 500,
        };
        let scope = HttpsCredentialScope::new(
            "git.example",
            443,
            "/owner/repo.git",
            HttpsCredentialAction::Read,
        )
        .unwrap();
        let mut frame =
            encode_credential_agent_request(session, 1, 2, &scope, &capability).unwrap();
        frame[75] ^= 1;
        assert!(decode_credential_agent_request(&frame, session, &capability).is_err());
        let request = CredentialAgentRequest {
            session,
            request_id: 1,
            credential_generation: 2,
            scope: scope.clone(),
        };
        let response =
            encode_credential_agent_response(&request, 510, Some(&[b'a'; 64]), &capability)
                .unwrap();
        assert!(
            decode_credential_agent_response(&response, session, 1, 3, &scope, &capability, 500)
                .is_err()
        );
        assert!(
            decode_credential_agent_response(&response, session, 1, 2, &scope, &wrong, 500)
                .is_err()
        );
        assert!(
            decode_credential_agent_response(&response, session, 1, 2, &scope, &capability, 511)
                .is_err()
        );
    }
}
