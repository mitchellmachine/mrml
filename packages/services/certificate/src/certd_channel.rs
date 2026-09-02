use mrml_crypto::{erase_secret_bytes, hmac_sha256, Sha256};

pub const CERTD_CHANNEL_HEADER_BYTES: usize = 96;
pub const MAX_CERTD_CHANNEL_PAYLOAD_BYTES: usize = 16 * 1024;
pub const CERTD_CHANNEL_CAPABILITY_BYTES: usize = 32;
const MAGIC: &[u8; 8] = b"MRMLCDV1";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CertdChannelRole {
    Gitd = 1,
    Acmed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CertdChannelOperation {
    Health = 1,
    GetIdentitySnapshot = 2,
    SignTls13CertificateVerify = 3,
    WaitForIdentityGeneration = 4,
    GetAcmeAccountPublicIdentity = 16,
    SignAcmeJws = 17,
    CreateTlsKeyGeneration = 18,
    CreateCertificateSigningRequest = 19,
    StageCertificateCandidate = 20,
    ActivateCertificateGeneration = 21,
    RetireCertificateGeneration = 22,
    GetCertificateLifecycleStatus = 23,
    RequestCertificateKeyProofForRevocation = 24,
    GetActiveCertificateForRevocation = 25,
    CreateAccountRolloverInnerJws = 26,
}

impl CertdChannelOperation {
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Health,
            2 => Self::GetIdentitySnapshot,
            3 => Self::SignTls13CertificateVerify,
            4 => Self::WaitForIdentityGeneration,
            16 => Self::GetAcmeAccountPublicIdentity,
            17 => Self::SignAcmeJws,
            18 => Self::CreateTlsKeyGeneration,
            19 => Self::CreateCertificateSigningRequest,
            20 => Self::StageCertificateCandidate,
            21 => Self::ActivateCertificateGeneration,
            22 => Self::RetireCertificateGeneration,
            23 => Self::GetCertificateLifecycleStatus,
            24 => Self::RequestCertificateKeyProofForRevocation,
            25 => Self::GetActiveCertificateForRevocation,
            26 => Self::CreateAccountRolloverInnerJws,
            _ => return None,
        })
    }

    pub const fn allowed_for(self, role: CertdChannelRole) -> bool {
        match role {
            CertdChannelRole::Gitd => matches!(
                self,
                Self::Health
                    | Self::GetIdentitySnapshot
                    | Self::SignTls13CertificateVerify
                    | Self::WaitForIdentityGeneration
            ),
            CertdChannelRole::Acmed => matches!(
                self,
                Self::Health
                    | Self::GetAcmeAccountPublicIdentity
                    | Self::SignAcmeJws
                    | Self::CreateTlsKeyGeneration
                    | Self::CreateCertificateSigningRequest
                    | Self::StageCertificateCandidate
                    | Self::ActivateCertificateGeneration
                    | Self::RetireCertificateGeneration
                    | Self::GetCertificateLifecycleStatus
                    | Self::RequestCertificateKeyProofForRevocation
                    | Self::GetActiveCertificateForRevocation
                    | Self::CreateAccountRolloverInnerJws
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertdPeerIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertdChannelPolicy {
    pub role: CertdChannelRole,
    pub peer: CertdPeerIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertdChannelRequest<'a> {
    pub role: CertdChannelRole,
    pub operation: CertdChannelOperation,
    pub request_id: u64,
    pub peer: CertdPeerIdentity,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdChannelError {
    InvalidCapability,
    InvalidFrame,
    WrongRole,
    UnauthorizedOperation,
    UnauthorizedPeer,
    PayloadLimit,
    OutputTooSmall,
    AuthenticationFailed,
    Replay,
}

pub struct CertdChannelCapability {
    key: [u8; CERTD_CHANNEL_CAPABILITY_BYTES],
}

impl CertdChannelCapability {
    pub fn new(key: [u8; CERTD_CHANNEL_CAPABILITY_BYTES]) -> Result<Self, CertdChannelError> {
        if key == [0; CERTD_CHANNEL_CAPABILITY_BYTES] {
            return Err(CertdChannelError::InvalidCapability);
        }
        Ok(Self { key })
    }

    fn tag(&self, authenticated_header: &[u8], payload: &[u8]) -> [u8; 32] {
        hmac_sha256(
            &self.key,
            &[b"MRML certd channel v1", authenticated_header, payload],
        )
    }
}

impl Drop for CertdChannelCapability {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.key);
    }
}

pub struct CertdReplayWindow {
    last_request_id: u64,
}

impl CertdReplayWindow {
    pub const fn new() -> Self {
        Self { last_request_id: 0 }
    }

    pub fn accept(&mut self, request_id: u64) -> Result<(), CertdChannelError> {
        if request_id == 0 || request_id <= self.last_request_id {
            return Err(CertdChannelError::Replay);
        }
        self.last_request_id = request_id;
        Ok(())
    }
}

impl Default for CertdReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode_certd_channel_request(
    request: CertdChannelRequest<'_>,
    capability: &CertdChannelCapability,
    output: &mut [u8],
) -> Result<usize, CertdChannelError> {
    validate_request(request)?;
    let written = CERTD_CHANNEL_HEADER_BYTES
        .checked_add(request.payload.len())
        .ok_or(CertdChannelError::PayloadLimit)?;
    if output.len() < written {
        return Err(CertdChannelError::OutputTooSmall);
    }
    output[..written].fill(0);
    output[..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_be_bytes());
    output[10] = request.role as u8;
    output[11] = request.operation as u8;
    output[12..20].copy_from_slice(&request.request_id.to_be_bytes());
    output[20..24].copy_from_slice(&(request.payload.len() as u32).to_be_bytes());
    output[24..28].copy_from_slice(&request.peer.uid.to_be_bytes());
    output[28..32].copy_from_slice(&request.peer.gid.to_be_bytes());
    output[32..64].copy_from_slice(&Sha256::digest(request.payload));
    output[CERTD_CHANNEL_HEADER_BYTES..written].copy_from_slice(request.payload);
    let tag = capability.tag(&output[..64], request.payload);
    output[64..96].copy_from_slice(&tag);
    Ok(written)
}

pub fn decode_certd_channel_request<'a>(
    input: &'a [u8],
    observed_peer: CertdPeerIdentity,
    policy: CertdChannelPolicy,
    capability: &CertdChannelCapability,
    replay: &mut CertdReplayWindow,
) -> Result<CertdChannelRequest<'a>, CertdChannelError> {
    if input.len() < CERTD_CHANNEL_HEADER_BYTES
        || &input[..8] != MAGIC
        || u16::from_be_bytes([input[8], input[9]]) != VERSION
    {
        return Err(CertdChannelError::InvalidFrame);
    }
    let role = match input[10] {
        1 => CertdChannelRole::Gitd,
        2 => CertdChannelRole::Acmed,
        _ => return Err(CertdChannelError::InvalidFrame),
    };
    let operation =
        CertdChannelOperation::parse(input[11]).ok_or(CertdChannelError::UnauthorizedOperation)?;
    let payload_length = u32::from_be_bytes(
        input[20..24]
            .try_into()
            .map_err(|_| CertdChannelError::InvalidFrame)?,
    ) as usize;
    if payload_length > MAX_CERTD_CHANNEL_PAYLOAD_BYTES
        || CERTD_CHANNEL_HEADER_BYTES.checked_add(payload_length) != Some(input.len())
    {
        return Err(CertdChannelError::PayloadLimit);
    }
    if role != policy.role {
        return Err(CertdChannelError::WrongRole);
    }
    let claimed_peer = CertdPeerIdentity {
        uid: u32::from_be_bytes(
            input[24..28]
                .try_into()
                .map_err(|_| CertdChannelError::InvalidFrame)?,
        ),
        gid: u32::from_be_bytes(
            input[28..32]
                .try_into()
                .map_err(|_| CertdChannelError::InvalidFrame)?,
        ),
    };
    if observed_peer != policy.peer || claimed_peer != observed_peer {
        return Err(CertdChannelError::UnauthorizedPeer);
    }
    if !operation.allowed_for(role) {
        return Err(CertdChannelError::UnauthorizedOperation);
    }
    let payload = &input[CERTD_CHANNEL_HEADER_BYTES..];
    if input[32..64] != Sha256::digest(payload) {
        return Err(CertdChannelError::InvalidFrame);
    }
    let expected = capability.tag(&input[..64], payload);
    let mut difference = 0u8;
    for index in 0..expected.len() {
        difference |= expected[index] ^ input[64 + index];
    }
    if difference != 0 {
        return Err(CertdChannelError::AuthenticationFailed);
    }
    let request_id = u64::from_be_bytes(
        input[12..20]
            .try_into()
            .map_err(|_| CertdChannelError::InvalidFrame)?,
    );
    replay.accept(request_id)?;
    Ok(CertdChannelRequest {
        role,
        operation,
        request_id,
        peer: claimed_peer,
        payload,
    })
}

fn validate_request(request: CertdChannelRequest<'_>) -> Result<(), CertdChannelError> {
    if request.request_id == 0 {
        return Err(CertdChannelError::Replay);
    }
    if request.payload.len() > MAX_CERTD_CHANNEL_PAYLOAD_BYTES {
        return Err(CertdChannelError::PayloadLimit);
    }
    if !request.operation.allowed_for(request.role) {
        return Err(CertdChannelError::UnauthorizedOperation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_capability(value: u8) -> CertdChannelCapability {
        CertdChannelCapability::new([value; 32]).unwrap()
    }

    #[test]
    fn exact_role_peer_capability_and_replay_are_enforced() {
        let peer = CertdPeerIdentity {
            uid: 21001,
            gid: 21902,
        };
        let policy = CertdChannelPolicy {
            role: CertdChannelRole::Gitd,
            peer,
        };
        let request = CertdChannelRequest {
            role: CertdChannelRole::Gitd,
            operation: CertdChannelOperation::SignTls13CertificateVerify,
            request_id: 7,
            peer,
            payload: &[9; 32],
        };
        let capability = make_capability(0x41);
        let mut encoded = [0u8; 256];
        let length = encode_certd_channel_request(request, &capability, &mut encoded).unwrap();
        let mut replay = CertdReplayWindow::new();
        assert_eq!(
            decode_certd_channel_request(
                &encoded[..length],
                peer,
                policy,
                &capability,
                &mut replay,
            )
            .unwrap(),
            request
        );
        assert_eq!(
            decode_certd_channel_request(
                &encoded[..length],
                peer,
                policy,
                &capability,
                &mut replay,
            ),
            Err(CertdChannelError::Replay)
        );
        let mut wrong = CertdReplayWindow::new();
        assert_eq!(
            decode_certd_channel_request(
                &encoded[..length],
                peer,
                policy,
                &make_capability(0x42),
                &mut wrong,
            ),
            Err(CertdChannelError::AuthenticationFailed)
        );
    }

    #[test]
    fn role_operation_confusion_and_mutation_fail_closed() {
        let peer = CertdPeerIdentity {
            uid: 21004,
            gid: 21903,
        };
        let request = CertdChannelRequest {
            role: CertdChannelRole::Acmed,
            operation: CertdChannelOperation::CreateCertificateSigningRequest,
            request_id: 9,
            peer,
            payload: b"canonical identifiers",
        };
        let capability = make_capability(0x51);
        let mut encoded = [0u8; 256];
        let length = encode_certd_channel_request(request, &capability, &mut encoded).unwrap();
        encoded[length - 1] ^= 1;
        assert!(matches!(
            decode_certd_channel_request(
                &encoded[..length],
                peer,
                CertdChannelPolicy {
                    role: CertdChannelRole::Acmed,
                    peer
                },
                &capability,
                &mut CertdReplayWindow::new(),
            ),
            Err(CertdChannelError::InvalidFrame)
        ));
        let gitd_request = CertdChannelRequest {
            role: CertdChannelRole::Gitd,
            ..request
        };
        assert_eq!(
            encode_certd_channel_request(gitd_request, &capability, &mut encoded),
            Err(CertdChannelError::UnauthorizedOperation)
        );
    }
}
