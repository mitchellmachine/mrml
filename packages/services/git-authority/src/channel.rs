use mrml_crypto::{erase_secret_bytes, hmac_sha256, Sha256};

const MAGIC: &[u8; 8] = b"MRMLGAV1";
const VERSION: u16 = 1;
pub const AUTHORITY_HEADER_BYTES: usize = 98;
pub const AUTHORITY_CAPABILITY_BYTES: usize = 32;
pub const MAX_AUTHORITY_PAYLOAD_BYTES: usize = 1024 * 1024 + 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorityFrameKind {
    Request = 1,
    Response = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorityOperation {
    Health = 1,
    AuthorizeReceive = 2,
    AuthorizeRefTransaction = 3,
    VerifyCommit = 4,
    VerifyLegacyCommit = 5,
    SignReceipt = 6,
    VerifyReceipt = 7,
}

impl AuthorityOperation {
    pub fn from_code(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Health,
            2 => Self::AuthorizeReceive,
            3 => Self::AuthorizeRefTransaction,
            4 => Self::VerifyCommit,
            5 => Self::VerifyLegacyCommit,
            6 => Self::SignReceipt,
            7 => Self::VerifyReceipt,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityPeer {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityFrame<'a> {
    pub kind: AuthorityFrameKind,
    pub operation: AuthorityOperation,
    pub request_id: u64,
    pub status: u16,
    pub peer: AuthorityPeer,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    InvalidCapability,
    InvalidFrame,
    WrongKind,
    UnauthorizedPeer,
    AuthenticationFailed,
    Replay,
    PayloadLimit,
    OutputTooSmall,
}

pub struct AuthorityCapability {
    key: [u8; AUTHORITY_CAPABILITY_BYTES],
}

impl AuthorityCapability {
    pub fn new(key: [u8; AUTHORITY_CAPABILITY_BYTES]) -> Result<Self, AuthorityError> {
        if key == [0; AUTHORITY_CAPABILITY_BYTES] {
            return Err(AuthorityError::InvalidCapability);
        }
        Ok(Self { key })
    }

    fn tag(&self, header: &[u8], payload: &[u8]) -> [u8; 32] {
        hmac_sha256(
            &self.key,
            &[b"MRML git authority channel v1", header, payload],
        )
    }
}

impl Drop for AuthorityCapability {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.key);
    }
}

pub struct AuthorityReplayWindow {
    last_request_id: u64,
}

impl AuthorityReplayWindow {
    pub const fn new() -> Self {
        Self { last_request_id: 0 }
    }

    pub fn accept(&mut self, request_id: u64) -> Result<(), AuthorityError> {
        if request_id == 0 || request_id <= self.last_request_id {
            return Err(AuthorityError::Replay);
        }
        self.last_request_id = request_id;
        Ok(())
    }
}

impl Default for AuthorityReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode_frame(
    frame: AuthorityFrame<'_>,
    capability: &AuthorityCapability,
    output: &mut [u8],
) -> Result<usize, AuthorityError> {
    if frame.request_id == 0 || frame.payload.len() > MAX_AUTHORITY_PAYLOAD_BYTES {
        return Err(AuthorityError::PayloadLimit);
    }
    if frame.kind == AuthorityFrameKind::Request && frame.status != 0 {
        return Err(AuthorityError::InvalidFrame);
    }
    let length = AUTHORITY_HEADER_BYTES
        .checked_add(frame.payload.len())
        .ok_or(AuthorityError::PayloadLimit)?;
    let encoded = output
        .get_mut(..length)
        .ok_or(AuthorityError::OutputTooSmall)?;
    encoded.fill(0);
    encoded[..8].copy_from_slice(MAGIC);
    encoded[8..10].copy_from_slice(&VERSION.to_be_bytes());
    encoded[10] = frame.kind as u8;
    encoded[11] = frame.operation as u8;
    encoded[12..20].copy_from_slice(&frame.request_id.to_be_bytes());
    encoded[20..24].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    encoded[24..28].copy_from_slice(&frame.peer.uid.to_be_bytes());
    encoded[28..32].copy_from_slice(&frame.peer.gid.to_be_bytes());
    encoded[32..34].copy_from_slice(&frame.status.to_be_bytes());
    encoded[34..66].copy_from_slice(&Sha256::digest(frame.payload));
    encoded[AUTHORITY_HEADER_BYTES..].copy_from_slice(frame.payload);
    let tag = capability.tag(&encoded[..66], frame.payload);
    encoded[66..98].copy_from_slice(&tag);
    Ok(length)
}

pub fn decode_frame<'a>(
    input: &'a [u8],
    expected_kind: AuthorityFrameKind,
    observed_peer: AuthorityPeer,
    expected_peer: AuthorityPeer,
    capability: &AuthorityCapability,
    replay: &mut AuthorityReplayWindow,
) -> Result<AuthorityFrame<'a>, AuthorityError> {
    if input.len() < AUTHORITY_HEADER_BYTES
        || &input[..8] != MAGIC
        || u16::from_be_bytes([input[8], input[9]]) != VERSION
    {
        return Err(AuthorityError::InvalidFrame);
    }
    let kind = match input[10] {
        1 => AuthorityFrameKind::Request,
        2 => AuthorityFrameKind::Response,
        _ => return Err(AuthorityError::InvalidFrame),
    };
    if kind != expected_kind {
        return Err(AuthorityError::WrongKind);
    }
    let operation = AuthorityOperation::from_code(input[11]).ok_or(AuthorityError::InvalidFrame)?;
    let payload_length = u32::from_be_bytes(
        input[20..24]
            .try_into()
            .map_err(|_| AuthorityError::InvalidFrame)?,
    ) as usize;
    if payload_length > MAX_AUTHORITY_PAYLOAD_BYTES
        || AUTHORITY_HEADER_BYTES.checked_add(payload_length) != Some(input.len())
    {
        return Err(AuthorityError::PayloadLimit);
    }
    let claimed_peer = AuthorityPeer {
        uid: u32::from_be_bytes(
            input[24..28]
                .try_into()
                .map_err(|_| AuthorityError::InvalidFrame)?,
        ),
        gid: u32::from_be_bytes(
            input[28..32]
                .try_into()
                .map_err(|_| AuthorityError::InvalidFrame)?,
        ),
    };
    if observed_peer != expected_peer || claimed_peer != observed_peer {
        return Err(AuthorityError::UnauthorizedPeer);
    }
    let status = u16::from_be_bytes([input[32], input[33]]);
    if kind == AuthorityFrameKind::Request && status != 0 {
        return Err(AuthorityError::InvalidFrame);
    }
    let payload = &input[AUTHORITY_HEADER_BYTES..];
    if input[34..66] != Sha256::digest(payload) {
        return Err(AuthorityError::InvalidFrame);
    }
    let expected_tag = capability.tag(&input[..66], payload);
    let mut difference = 0u8;
    for index in 0..expected_tag.len() {
        difference |= expected_tag[index] ^ input[66 + index];
    }
    if difference != 0 {
        return Err(AuthorityError::AuthenticationFailed);
    }
    let request_id = u64::from_be_bytes(
        input[12..20]
            .try_into()
            .map_err(|_| AuthorityError::InvalidFrame)?,
    );
    replay.accept(request_id)?;
    Ok(AuthorityFrame {
        kind,
        operation,
        request_id,
        status,
        peer: claimed_peer,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_authenticated_frame_round_trips_and_replay_fails() {
        let capability = AuthorityCapability::new([0x51; 32]).unwrap();
        let peer = AuthorityPeer {
            uid: 21001,
            gid: 21901,
        };
        let frame = AuthorityFrame {
            kind: AuthorityFrameKind::Request,
            operation: AuthorityOperation::AuthorizeRefTransaction,
            request_id: 7,
            status: 0,
            peer,
            payload: b"exact transaction",
        };
        let mut encoded = [0u8; 256];
        let length = encode_frame(frame, &capability, &mut encoded).unwrap();
        let mut replay = AuthorityReplayWindow::new();
        assert_eq!(
            decode_frame(
                &encoded[..length],
                AuthorityFrameKind::Request,
                peer,
                peer,
                &capability,
                &mut replay,
            )
            .unwrap(),
            frame
        );
        assert_eq!(
            decode_frame(
                &encoded[..length],
                AuthorityFrameKind::Request,
                peer,
                peer,
                &capability,
                &mut replay,
            ),
            Err(AuthorityError::Replay)
        );
    }

    #[test]
    fn tamper_wrong_peer_unknown_operation_and_oversize_fail_closed() {
        let capability = AuthorityCapability::new([0x52; 32]).unwrap();
        let peer = AuthorityPeer {
            uid: 21001,
            gid: 21901,
        };
        let frame = AuthorityFrame {
            kind: AuthorityFrameKind::Request,
            operation: AuthorityOperation::Health,
            request_id: 1,
            status: 0,
            peer,
            payload: b"health",
        };
        let mut encoded = [0u8; 256];
        let length = encode_frame(frame, &capability, &mut encoded).unwrap();
        encoded[AUTHORITY_HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_frame(
                &encoded[..length],
                AuthorityFrameKind::Request,
                peer,
                peer,
                &capability,
                &mut AuthorityReplayWindow::new(),
            ),
            Err(AuthorityError::InvalidFrame)
        );
        encoded[AUTHORITY_HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_frame(
                &encoded[..length],
                AuthorityFrameKind::Request,
                AuthorityPeer {
                    uid: 21002,
                    gid: 21901
                },
                peer,
                &capability,
                &mut AuthorityReplayWindow::new(),
            ),
            Err(AuthorityError::UnauthorizedPeer)
        );
        encoded[11] = 255;
        assert_eq!(
            decode_frame(
                &encoded[..length],
                AuthorityFrameKind::Request,
                peer,
                peer,
                &capability,
                &mut AuthorityReplayWindow::new(),
            ),
            Err(AuthorityError::InvalidFrame)
        );
        assert_eq!(
            encode_frame(
                AuthorityFrame {
                    payload: &[0u8; MAX_AUTHORITY_PAYLOAD_BYTES + 1],
                    ..frame
                },
                &capability,
                &mut [],
            ),
            Err(AuthorityError::PayloadLimit)
        );
    }
}
