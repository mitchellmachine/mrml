use crate::{MAX_CERTD_CHANNEL_PAYLOAD_BYTES, PemCertificateChain};
use mrml_acme::CertificateProfile;

const MAGIC: &[u8; 8] = b"MRMLCCV1";
const HEADER_BYTES: usize = 96;
const STATE_MAGIC: &[u8; 8] = b"MRMLCSV1";
pub const CERTD_CANDIDATE_STATE_BYTES: usize = 208;
pub const MAX_CERTD_CANDIDATE_CHAIN_BYTES: usize = MAX_CERTD_CHANNEL_PAYLOAD_BYTES - HEADER_BYTES;

pub struct CertdCandidateRequest {
    pub identity: [u8; 16],
    pub directory_generation: u64,
    pub account_generation: u64,
    pub key_generation: u64,
    pub policy_generation: u64,
    pub order_url_digest: [u8; 32],
    pub profile: CertificateProfile,
    pub chain: PemCertificateChain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdCandidateProtocolError {
    InvalidRequest,
    InvalidProfile,
    InvalidChain,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CertdCandidateStage {
    Staged = 1,
    Active = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertdCandidateState {
    pub stage: CertdCandidateStage,
    pub identity: [u8; 16],
    pub directory_generation: u64,
    pub account_generation: u64,
    pub key_generation: u64,
    pub policy_generation: u64,
    pub order_url_digest: [u8; 32],
    pub chain_digest: [u8; 32],
    pub leaf_spki_digest: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub request_digest: [u8; 32],
}

impl CertdCandidateState {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, CertdCandidateProtocolError> {
        if output.len() < CERTD_CANDIDATE_STATE_BYTES
            || self.identity == [0; 16]
            || self.directory_generation == 0
            || self.account_generation == 0
            || self.key_generation == 0
            || self.policy_generation == 0
            || self.order_url_digest == [0; 32]
            || self.chain_digest == [0; 32]
            || self.leaf_spki_digest == [0; 32]
            || self.not_before >= self.not_after
            || self.request_digest == [0; 32]
        {
            return Err(CertdCandidateProtocolError::InvalidRequest);
        }
        output[..CERTD_CANDIDATE_STATE_BYTES].fill(0);
        output[..8].copy_from_slice(STATE_MAGIC);
        output[8] = self.stage as u8;
        output[16..32].copy_from_slice(&self.identity);
        output[32..40].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[40..48].copy_from_slice(&self.account_generation.to_be_bytes());
        output[48..56].copy_from_slice(&self.key_generation.to_be_bytes());
        output[56..64].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[64..96].copy_from_slice(&self.order_url_digest);
        output[96..128].copy_from_slice(&self.chain_digest);
        output[128..160].copy_from_slice(&self.leaf_spki_digest);
        output[160..168].copy_from_slice(&self.not_before.to_be_bytes());
        output[168..176].copy_from_slice(&self.not_after.to_be_bytes());
        output[176..208].copy_from_slice(&self.request_digest);
        Ok(CERTD_CANDIDATE_STATE_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CertdCandidateProtocolError> {
        if input.len() != CERTD_CANDIDATE_STATE_BYTES
            || input.get(..8) != Some(STATE_MAGIC)
            || input[9..16].iter().any(|byte| *byte != 0)
        {
            return Err(CertdCandidateProtocolError::InvalidRequest);
        }
        let state = Self {
            stage: match input[8] {
                1 => CertdCandidateStage::Staged,
                2 => CertdCandidateStage::Active,
                _ => return Err(CertdCandidateProtocolError::InvalidRequest),
            },
            identity: copy(&input[16..32])?,
            directory_generation: read_u64(&input[32..40])?,
            account_generation: read_u64(&input[40..48])?,
            key_generation: read_u64(&input[48..56])?,
            policy_generation: read_u64(&input[56..64])?,
            order_url_digest: copy(&input[64..96])?,
            chain_digest: copy(&input[96..128])?,
            leaf_spki_digest: copy(&input[128..160])?,
            not_before: read_u64(&input[160..168])?,
            not_after: read_u64(&input[168..176])?,
            request_digest: copy(&input[176..208])?,
        };
        let mut canonical = [0u8; CERTD_CANDIDATE_STATE_BYTES];
        state.encode(&mut canonical)?;
        if canonical != input {
            return Err(CertdCandidateProtocolError::InvalidRequest);
        }
        Ok(state)
    }
}

fn copy<const N: usize>(input: &[u8]) -> Result<[u8; N], CertdCandidateProtocolError> {
    input
        .try_into()
        .map_err(|_| CertdCandidateProtocolError::InvalidRequest)
}

pub fn encode_certd_candidate_request(
    request: &CertdCandidateRequest,
    output: &mut [u8],
) -> Result<usize, CertdCandidateProtocolError> {
    let profile = request.profile.name().as_bytes();
    let chain_length = (0..request.chain.count()).try_fold(0usize, |length, index| {
        request
            .chain
            .certificate(index)
            .and_then(|certificate| length.checked_add(2 + certificate.len()))
    });
    let chain_length = chain_length.ok_or(CertdCandidateProtocolError::InvalidChain)?;
    let written = HEADER_BYTES
        .checked_add(profile.len())
        .and_then(|value| value.checked_add(chain_length))
        .ok_or(CertdCandidateProtocolError::InvalidRequest)?;
    if request.identity == [0; 16]
        || request.directory_generation == 0
        || request.account_generation == 0
        || request.key_generation == 0
        || request.policy_generation == 0
        || request.order_url_digest == [0; 32]
        || profile.is_empty()
        || profile.len() > 32
        || request.chain.count() == 0
        || chain_length > MAX_CERTD_CANDIDATE_CHAIN_BYTES
    {
        return Err(CertdCandidateProtocolError::InvalidRequest);
    }
    if output.len() < written || written > MAX_CERTD_CHANNEL_PAYLOAD_BYTES {
        return Err(CertdCandidateProtocolError::OutputTooSmall);
    }
    output[..written].fill(0);
    output[..8].copy_from_slice(MAGIC);
    output[8] = profile.len() as u8;
    output[9] = request.chain.count() as u8;
    output[12..16].copy_from_slice(&(chain_length as u32).to_be_bytes());
    output[16..32].copy_from_slice(&request.identity);
    output[32..40].copy_from_slice(&request.directory_generation.to_be_bytes());
    output[40..48].copy_from_slice(&request.account_generation.to_be_bytes());
    output[48..56].copy_from_slice(&request.key_generation.to_be_bytes());
    output[56..64].copy_from_slice(&request.policy_generation.to_be_bytes());
    output[64..96].copy_from_slice(&request.order_url_digest);
    output[96..96 + profile.len()].copy_from_slice(profile);
    let mut cursor = 96 + profile.len();
    for index in 0..request.chain.count() {
        let certificate = request
            .chain
            .certificate(index)
            .ok_or(CertdCandidateProtocolError::InvalidChain)?;
        output[cursor..cursor + 2].copy_from_slice(&(certificate.len() as u16).to_be_bytes());
        cursor += 2;
        output[cursor..cursor + certificate.len()].copy_from_slice(certificate);
        cursor += certificate.len();
    }
    Ok(written)
}

pub fn decode_certd_candidate_request(
    input: &[u8],
) -> Result<CertdCandidateRequest, CertdCandidateProtocolError> {
    if input.len() < HEADER_BYTES
        || input.get(..8) != Some(MAGIC)
        || input[10..12].iter().any(|byte| *byte != 0)
        || input.len() > MAX_CERTD_CHANNEL_PAYLOAD_BYTES
    {
        return Err(CertdCandidateProtocolError::InvalidRequest);
    }
    let profile_length = usize::from(input[8]);
    let certificate_count = usize::from(input[9]);
    let chain_length = u32::from_be_bytes(
        input[12..16]
            .try_into()
            .map_err(|_| CertdCandidateProtocolError::InvalidRequest)?,
    ) as usize;
    if profile_length == 0
        || profile_length > 32
        || certificate_count == 0
        || certificate_count > crate::MAX_CERTIFICATES
        || chain_length == 0
        || chain_length > MAX_CERTD_CANDIDATE_CHAIN_BYTES
        || HEADER_BYTES
            .checked_add(profile_length)
            .and_then(|value| value.checked_add(chain_length))
            != Some(input.len())
    {
        return Err(CertdCandidateProtocolError::InvalidRequest);
    }
    let directory_generation = read_u64(&input[32..40])?;
    let profile = core::str::from_utf8(&input[96..96 + profile_length])
        .map_err(|_| CertdCandidateProtocolError::InvalidProfile)?;
    let mut certificates = [&[][..]; crate::MAX_CERTIFICATES];
    let mut cursor = 96 + profile_length;
    for certificate in certificates.iter_mut().take(certificate_count) {
        let length_bytes = input
            .get(cursor..cursor + 2)
            .ok_or(CertdCandidateProtocolError::InvalidChain)?;
        let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        cursor += 2;
        let end = cursor
            .checked_add(length)
            .ok_or(CertdCandidateProtocolError::InvalidChain)?;
        *certificate = input
            .get(cursor..end)
            .ok_or(CertdCandidateProtocolError::InvalidChain)?;
        cursor = end;
    }
    if cursor != input.len() {
        return Err(CertdCandidateProtocolError::InvalidChain);
    }
    let request = CertdCandidateRequest {
        identity: input[16..32]
            .try_into()
            .map_err(|_| CertdCandidateProtocolError::InvalidRequest)?,
        directory_generation,
        account_generation: read_u64(&input[40..48])?,
        key_generation: read_u64(&input[48..56])?,
        policy_generation: read_u64(&input[56..64])?,
        order_url_digest: input[64..96]
            .try_into()
            .map_err(|_| CertdCandidateProtocolError::InvalidRequest)?,
        profile: CertificateProfile::parse(profile, directory_generation)
            .map_err(|_| CertdCandidateProtocolError::InvalidProfile)?,
        chain: PemCertificateChain::from_der_certificates(&certificates[..certificate_count])
            .map_err(|_| CertdCandidateProtocolError::InvalidChain)?,
    };
    let mut canonical = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let length = encode_certd_candidate_request(&request, &mut canonical)?;
    if canonical[..length] != *input {
        return Err(CertdCandidateProtocolError::InvalidRequest);
    }
    Ok(request)
}

fn read_u64(input: &[u8]) -> Result<u64, CertdCandidateProtocolError> {
    let value = u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| CertdCandidateProtocolError::InvalidRequest)?,
    );
    if value == 0 {
        Err(CertdCandidateProtocolError::InvalidRequest)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CertdCandidateRequest {
        CertdCandidateRequest {
            identity: [1; 16],
            directory_generation: 2,
            account_generation: 3,
            key_generation: 4,
            policy_generation: 5,
            order_url_digest: [6; 32],
            profile: CertificateProfile::parse("classic", 2).unwrap(),
            chain: PemCertificateChain::parse(
                b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            )
            .unwrap(),
        }
    }

    #[test]
    fn candidate_request_round_trips_exact_bounded_bindings() {
        let request = request();
        let mut encoded = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
        let length = encode_certd_candidate_request(&request, &mut encoded).unwrap();
        let decoded = decode_certd_candidate_request(&encoded[..length]).unwrap();
        assert_eq!(decoded.identity, request.identity);
        assert_eq!(decoded.key_generation, request.key_generation);
        assert_eq!(decoded.order_url_digest, request.order_url_digest);
        assert_eq!(decoded.chain.chain_digest(), request.chain.chain_digest());
        encoded[64] ^= 1;
        assert_ne!(
            decode_certd_candidate_request(&encoded[..length])
                .unwrap()
                .order_url_digest,
            request.order_url_digest
        );
        encoded[10] = 1;
        assert!(decode_certd_candidate_request(&encoded[..length]).is_err());
    }

    #[test]
    fn candidate_state_round_trips_and_rejects_reserved_mutation() {
        let state = CertdCandidateState {
            stage: CertdCandidateStage::Staged,
            identity: [1; 16],
            directory_generation: 2,
            account_generation: 3,
            key_generation: 4,
            policy_generation: 5,
            order_url_digest: [6; 32],
            chain_digest: [7; 32],
            leaf_spki_digest: [8; 32],
            not_before: 9,
            not_after: 10,
            request_digest: [11; 32],
        };
        let mut encoded = [0u8; CERTD_CANDIDATE_STATE_BYTES];
        state.encode(&mut encoded).unwrap();
        assert!(CertdCandidateState::decode(&encoded).unwrap() == state);
        encoded[9] = 1;
        assert!(CertdCandidateState::decode(&encoded).is_err());
    }
}
