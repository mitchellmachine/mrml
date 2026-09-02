#![no_std]

use mrml_acme::{
    AcmeDirectory, AcmeUrl, CertificateProfile, DnsIdentifier, JwkThumbprint, MAX_AUTHORIZATIONS,
    MAX_CSR_IDENTIFIERS, MAX_URL_BYTES, OrderState, OwnerTermsApproval,
};
use mrml_certificate::{
    Dns01PublicationReceipt, Dns01PublicationRequest, Dns01RecordName, Dns01TxtValue,
    MAX_DNS01_PROVIDER_RECORD_ID_BYTES, RenewalPolicy, certd_identifier_set_digest,
    dns01_publication_binding,
};
use mrml_crypto::Sha256;
use mrml_json::Value;

pub const MAX_ACMED_CONFIG_BYTES: usize = 16 * 1024;
const ACCOUNT_RECORD_MAGIC: &[u8; 8] = b"MRMLACA1";
const ACCOUNT_RECORD_HEADER_BYTES: usize = 116;
const CHANNEL_REQUEST_MAGIC: &[u8; 8] = b"MRMLRID1";
pub const CHANNEL_REQUEST_RESERVATION: u64 = 1_000_000;
const ORDER_RECORD_MAGIC: &[u8; 8] = b"MRMLAOR1";
const ORDER_RECORD_HEADER_BYTES: usize = 130;
const CHALLENGE_RECORD_MAGIC: &[u8; 8] = b"MRMLACH1";
const FINALIZATION_RECORD_MAGIC: &[u8; 8] = b"MRMLAFN1";
const FINALIZATION_RECORD_BYTES: usize = 128;
const CHALLENGE_RECORD_HEADER_BYTES: usize = 146;
const REVOCATION_RECORD_MAGIC: &[u8; 8] = b"MRMLARV1";
pub const REVOCATION_RECORD_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcmedRequestIdReservation {
    pub next: u64,
    pub last: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedChannelRequestCounter {
    pub account_identity: [u8; 16],
    pub last_reserved: u64,
}

impl AcmedChannelRequestCounter {
    pub fn new(account_identity: [u8; 16]) -> Result<Self, AcmedAccountRecordError> {
        if account_identity == [0; 16] {
            return Err(AcmedAccountRecordError::InvalidState);
        }
        Ok(Self {
            account_identity,
            last_reserved: 0,
        })
    }

    pub fn reserve(&mut self) -> Result<AcmedRequestIdReservation, AcmedAccountRecordError> {
        let next = self
            .last_reserved
            .checked_add(1)
            .ok_or(AcmedAccountRecordError::InvalidState)?;
        let last = self
            .last_reserved
            .checked_add(CHANNEL_REQUEST_RESERVATION)
            .ok_or(AcmedAccountRecordError::InvalidState)?;
        self.last_reserved = last;
        Ok(AcmedRequestIdReservation { next, last })
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedAccountRecordError> {
        if output.len() < 32
            || self.account_identity == [0; 16]
            || self.last_reserved == 0
            || self.last_reserved % CHANNEL_REQUEST_RESERVATION != 0
        {
            return Err(if output.len() < 32 {
                AcmedAccountRecordError::OutputTooSmall
            } else {
                AcmedAccountRecordError::InvalidState
            });
        }
        output[..32].fill(0);
        output[..8].copy_from_slice(CHANNEL_REQUEST_MAGIC);
        output[8..24].copy_from_slice(&self.account_identity);
        output[24..32].copy_from_slice(&self.last_reserved.to_be_bytes());
        Ok(32)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcmedAccountRecordError> {
        if input.len() != 32 || input.get(..8) != Some(CHANNEL_REQUEST_MAGIC) {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let counter = Self {
            account_identity: input[8..24]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            last_reserved: read_u64(&input[24..32])?,
        };
        let mut canonical = [0u8; 32];
        counter.encode(&mut canonical)?;
        if canonical != input {
            return Err(AcmedAccountRecordError::Malformed);
        }
        Ok(counter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedAccountPhase {
    RequestMayHaveBeenSent = 1,
    Active = 2,
    RolloverMayHaveBeenSent = 3,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedAccountRecord {
    pub phase: AcmedAccountPhase,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub account_identity: [u8; 16],
    pub key_thumbprint: JwkThumbprint,
    pub contact_digest: [u8; 32],
    pub account_url: Option<AcmeUrl>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedAccountRecordError {
    InvalidState,
    OutputTooSmall,
    Malformed,
    PolicyMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedRevocationPhase {
    Prepared = 1,
    SubmissionMayHaveBeenSent = 2,
    Revoked = 3,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedRevocationRecord {
    pub phase: AcmedRevocationPhase,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub identity: [u8; 16],
    pub identity_generation: u64,
    pub revocation_generation: u64,
    pub certificate_id: mrml_acme::AriCertificateId,
    pub chain_digest: [u8; 32],
    pub reason: u8,
    pub authorization_digest: [u8; 32],
    pub transaction_digest: [u8; 32],
    pub revoked_at_unix: u64,
}

impl AcmedRevocationRecord {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedAccountRecordError> {
        let certificate_id = self.certificate_id.as_str().as_bytes();
        let revoked = self.phase == AcmedRevocationPhase::Revoked;
        if output.len() < REVOCATION_RECORD_BYTES
            || self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.identity == [0; 16]
            || self.identity_generation == 0
            || self.revocation_generation == 0
            || certificate_id.is_empty()
            || certificate_id.len() > mrml_acme::MAX_ARI_CERTIFICATE_ID
            || self.chain_digest == [0; 32]
            || !matches!(self.reason, 0 | 1 | 3 | 4 | 5 | 9)
            || self.authorization_digest == [0; 32]
            || revoked != (self.transaction_digest != [0; 32] && self.revoked_at_unix != 0)
            || (!revoked && (self.transaction_digest != [0; 32] || self.revoked_at_unix != 0))
        {
            return Err(if output.len() < REVOCATION_RECORD_BYTES {
                AcmedAccountRecordError::OutputTooSmall
            } else {
                AcmedAccountRecordError::InvalidState
            });
        }
        output[..REVOCATION_RECORD_BYTES].fill(0);
        output[..8].copy_from_slice(REVOCATION_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[9] = self.reason;
        output[10] = certificate_id.len() as u8;
        output[16..24].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[24..32].copy_from_slice(&self.account_generation.to_be_bytes());
        output[32..40].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[40..56].copy_from_slice(&self.identity);
        output[56..64].copy_from_slice(&self.identity_generation.to_be_bytes());
        output[64..72].copy_from_slice(&self.revocation_generation.to_be_bytes());
        output[72..104].copy_from_slice(&self.chain_digest);
        output[104..136].copy_from_slice(&self.authorization_digest);
        output[136..168].copy_from_slice(&self.transaction_digest);
        output[168..176].copy_from_slice(&self.revoked_at_unix.to_be_bytes());
        output[176..176 + certificate_id.len()].copy_from_slice(certificate_id);
        Ok(REVOCATION_RECORD_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcmedAccountRecordError> {
        if input.len() != REVOCATION_RECORD_BYTES
            || input.get(..8) != Some(REVOCATION_RECORD_MAGIC)
            || input[11..16].iter().any(|byte| *byte != 0)
        {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let id_length = usize::from(input[10]);
        if id_length == 0
            || id_length > mrml_acme::MAX_ARI_CERTIFICATE_ID
            || input[176 + id_length..].iter().any(|byte| *byte != 0)
        {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let certificate_id = core::str::from_utf8(&input[176..176 + id_length])
            .map_err(|_| AcmedAccountRecordError::Malformed)
            .and_then(|text| {
                mrml_acme::AriCertificateId::parse(text)
                    .map_err(|_| AcmedAccountRecordError::Malformed)
            })?;
        let record = Self {
            phase: match input[8] {
                1 => AcmedRevocationPhase::Prepared,
                2 => AcmedRevocationPhase::SubmissionMayHaveBeenSent,
                3 => AcmedRevocationPhase::Revoked,
                _ => return Err(AcmedAccountRecordError::Malformed),
            },
            reason: input[9],
            directory_generation: read_nonzero_u64(&input[16..24])?,
            account_generation: read_nonzero_u64(&input[24..32])?,
            policy_generation: read_nonzero_u64(&input[32..40])?,
            identity: input[40..56]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            identity_generation: read_nonzero_u64(&input[56..64])?,
            revocation_generation: read_nonzero_u64(&input[64..72])?,
            chain_digest: input[72..104]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            authorization_digest: input[104..136]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            transaction_digest: input[136..168]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            revoked_at_unix: u64::from_be_bytes(
                input[168..176]
                    .try_into()
                    .map_err(|_| AcmedAccountRecordError::Malformed)?,
            ),
            certificate_id,
        };
        let mut canonical = [0u8; REVOCATION_RECORD_BYTES];
        record.encode(&mut canonical)?;
        if canonical != input {
            return Err(AcmedAccountRecordError::Malformed);
        }
        Ok(record)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedAccountRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.identity != config.identity
        {
            Err(AcmedAccountRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }
}

fn read_nonzero_u64(input: &[u8]) -> Result<u64, AcmedAccountRecordError> {
    let value = read_u64(input)?;
    if value == 0 {
        Err(AcmedAccountRecordError::Malformed)
    } else {
        Ok(value)
    }
}

impl AcmedAccountRecord {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedAccountRecordError> {
        let url = self.account_url.as_ref().map(AcmeUrl::as_str).unwrap_or("");
        if self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.account_identity == [0; 16]
            || self.key_thumbprint.0 == [0; 32]
            || (self.phase == AcmedAccountPhase::RequestMayHaveBeenSent)
                == self.account_url.is_some()
            || url.len() > MAX_URL_BYTES
        {
            return Err(AcmedAccountRecordError::InvalidState);
        }
        let length = ACCOUNT_RECORD_HEADER_BYTES
            .checked_add(url.len())
            .ok_or(AcmedAccountRecordError::OutputTooSmall)?;
        if output.len() < length {
            return Err(AcmedAccountRecordError::OutputTooSmall);
        }
        output[..length].fill(0);
        output[..8].copy_from_slice(ACCOUNT_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[12..20].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[20..28].copy_from_slice(&self.account_generation.to_be_bytes());
        output[28..36].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[36..52].copy_from_slice(&self.account_identity);
        output[52..84].copy_from_slice(&self.key_thumbprint.0);
        output[84..116].copy_from_slice(&self.contact_digest);
        output[10..12].copy_from_slice(&(url.len() as u16).to_be_bytes());
        output[ACCOUNT_RECORD_HEADER_BYTES..length].copy_from_slice(url.as_bytes());
        Ok(length)
    }

    pub fn decode(
        input: &[u8],
        configured_directory: &AcmeUrl,
        allow_test_http: bool,
    ) -> Result<Self, AcmedAccountRecordError> {
        if input.len() < ACCOUNT_RECORD_HEADER_BYTES
            || input.get(..8) != Some(ACCOUNT_RECORD_MAGIC)
            || input[9] != 0
        {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let phase = match input[8] {
            1 => AcmedAccountPhase::RequestMayHaveBeenSent,
            2 => AcmedAccountPhase::Active,
            3 => AcmedAccountPhase::RolloverMayHaveBeenSent,
            _ => return Err(AcmedAccountRecordError::Malformed),
        };
        let url_length = usize::from(u16::from_be_bytes([input[10], input[11]]));
        if url_length > MAX_URL_BYTES || input.len() != ACCOUNT_RECORD_HEADER_BYTES + url_length {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let directory_generation = read_u64(&input[12..20])?;
        let account_generation = read_u64(&input[20..28])?;
        let policy_generation = read_u64(&input[28..36])?;
        let account_identity = input[36..52]
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?;
        let key_thumbprint = JwkThumbprint(
            input[52..84]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
        );
        let contact_digest = input[84..116]
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?;
        let account_url = if url_length == 0 {
            None
        } else {
            let text = core::str::from_utf8(&input[116..])
                .map_err(|_| AcmedAccountRecordError::Malformed)?;
            let url = AcmeUrl::parse(text, allow_test_http)
                .map_err(|_| AcmedAccountRecordError::Malformed)?;
            url.require_origin(configured_directory.origin())
                .map_err(|_| AcmedAccountRecordError::PolicyMismatch)?;
            Some(url)
        };
        let record = Self {
            phase,
            directory_generation,
            account_generation,
            policy_generation,
            account_identity,
            key_thumbprint,
            contact_digest,
            account_url,
        };
        let mut canonical = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = record.encode(&mut canonical)?;
        if canonical[..length] != *input {
            return Err(AcmedAccountRecordError::Malformed);
        }
        Ok(record)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedAccountRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.account_identity != config.account_identity
        {
            Err(AcmedAccountRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }
}

fn read_u64(input: &[u8]) -> Result<u64, AcmedAccountRecordError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedOrderPhase {
    RequestMayHaveBeenSent = 1,
    Created = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedOrderRecord {
    pub phase: AcmedOrderPhase,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub identity: [u8; 16],
    pub request_digest: [u8; 32],
    pub deadline_unix: u64,
    pub state: Option<OrderState>,
    pub order_url: Option<AcmeUrl>,
    pub finalize_url: Option<AcmeUrl>,
    pub certificate_url: Option<AcmeUrl>,
    pub authorization_urls: [Option<AcmeUrl>; MAX_AUTHORIZATIONS],
    pub authorization_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedOrderRecordError {
    InvalidState,
    OutputTooSmall,
    Malformed,
    PolicyMismatch,
}

impl AcmedOrderRecord {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedOrderRecordError> {
        let count = usize::from(self.authorization_count);
        if self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.identity == [0; 16]
            || self.request_digest == [0; 32]
            || self.deadline_unix == 0
            || count > MAX_AUTHORIZATIONS
            || self.authorization_urls[count..].iter().any(Option::is_some)
        {
            return Err(AcmedOrderRecordError::InvalidState);
        }
        let created = self.phase == AcmedOrderPhase::Created;
        if created
            != (self.state.is_some() && self.order_url.is_some() && self.finalize_url.is_some())
            || (!created
                && (self.certificate_url.is_some()
                    || count != 0
                    || self.authorization_urls.iter().any(Option::is_some)))
            || self.authorization_urls[..count].iter().any(Option::is_none)
        {
            return Err(AcmedOrderRecordError::InvalidState);
        }
        let order = text_url(self.order_url.as_ref());
        let finalize = text_url(self.finalize_url.as_ref());
        let certificate = text_url(self.certificate_url.as_ref());
        let mut length = ORDER_RECORD_HEADER_BYTES;
        for url in [order, finalize, certificate].into_iter().chain(
            self.authorization_urls[..count]
                .iter()
                .flatten()
                .map(AcmeUrl::as_str),
        ) {
            if url.len() > MAX_URL_BYTES {
                return Err(AcmedOrderRecordError::InvalidState);
            }
            length = length
                .checked_add(url.len())
                .ok_or(AcmedOrderRecordError::OutputTooSmall)?;
        }
        if output.len() < length {
            return Err(AcmedOrderRecordError::OutputTooSmall);
        }
        output[..length].fill(0);
        output[..8].copy_from_slice(ORDER_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[9] = self.state.map(encode_order_state).unwrap_or(0);
        output[10] = self.authorization_count;
        output[12..20].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[20..28].copy_from_slice(&self.account_generation.to_be_bytes());
        output[28..36].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[36..52].copy_from_slice(&self.identity);
        output[52..84].copy_from_slice(&self.request_digest);
        output[84..92].copy_from_slice(&self.deadline_unix.to_be_bytes());
        for (index, url) in [order, finalize, certificate]
            .into_iter()
            .chain(
                self.authorization_urls[..count]
                    .iter()
                    .flatten()
                    .map(AcmeUrl::as_str),
            )
            .enumerate()
        {
            let start = 92 + index * 2;
            output[start..start + 2].copy_from_slice(&(url.len() as u16).to_be_bytes());
        }
        let mut cursor = ORDER_RECORD_HEADER_BYTES;
        for url in [order, finalize, certificate].into_iter().chain(
            self.authorization_urls[..count]
                .iter()
                .flatten()
                .map(AcmeUrl::as_str),
        ) {
            output[cursor..cursor + url.len()].copy_from_slice(url.as_bytes());
            cursor += url.len();
        }
        Ok(length)
    }

    pub fn decode(
        input: &[u8],
        configured_directory: &AcmeUrl,
        allow_test_http: bool,
    ) -> Result<Self, AcmedOrderRecordError> {
        if input.len() < ORDER_RECORD_HEADER_BYTES
            || input.get(..8) != Some(ORDER_RECORD_MAGIC)
            || input[11] != 0
        {
            return Err(AcmedOrderRecordError::Malformed);
        }
        let phase = match input[8] {
            1 => AcmedOrderPhase::RequestMayHaveBeenSent,
            2 => AcmedOrderPhase::Created,
            _ => return Err(AcmedOrderRecordError::Malformed),
        };
        let state = if input[9] == 0 {
            None
        } else {
            Some(decode_order_state(input[9])?)
        };
        let count = usize::from(input[10]);
        if count > MAX_AUTHORIZATIONS {
            return Err(AcmedOrderRecordError::Malformed);
        }
        let mut lengths = [0usize; 3 + MAX_AUTHORIZATIONS];
        for (index, length) in lengths.iter_mut().enumerate() {
            let start = 92 + index * 2;
            *length = usize::from(u16::from_be_bytes([input[start], input[start + 1]]));
        }
        if lengths[3 + count..].iter().any(|length| *length != 0)
            || lengths
                .iter()
                .try_fold(ORDER_RECORD_HEADER_BYTES, |sum, value| {
                    sum.checked_add(*value)
                })
                != Some(input.len())
        {
            return Err(AcmedOrderRecordError::Malformed);
        }
        let mut cursor = ORDER_RECORD_HEADER_BYTES;
        let mut urls = [None; 3 + MAX_AUTHORIZATIONS];
        for (index, length) in lengths.iter().enumerate() {
            if *length == 0 {
                continue;
            }
            let end = cursor
                .checked_add(*length)
                .ok_or(AcmedOrderRecordError::Malformed)?;
            let text = core::str::from_utf8(
                input
                    .get(cursor..end)
                    .ok_or(AcmedOrderRecordError::Malformed)?,
            )
            .map_err(|_| AcmedOrderRecordError::Malformed)?;
            let url = AcmeUrl::parse(text, allow_test_http)
                .map_err(|_| AcmedOrderRecordError::Malformed)?;
            url.require_origin(configured_directory.origin())
                .map_err(|_| AcmedOrderRecordError::PolicyMismatch)?;
            urls[index] = Some(url);
            cursor = end;
        }
        let mut authorization_urls = [None; MAX_AUTHORIZATIONS];
        authorization_urls[..count].copy_from_slice(&urls[3..3 + count]);
        let record = Self {
            phase,
            directory_generation: read_order_u64(&input[12..20])?,
            account_generation: read_order_u64(&input[20..28])?,
            policy_generation: read_order_u64(&input[28..36])?,
            identity: input[36..52]
                .try_into()
                .map_err(|_| AcmedOrderRecordError::Malformed)?,
            request_digest: input[52..84]
                .try_into()
                .map_err(|_| AcmedOrderRecordError::Malformed)?,
            deadline_unix: read_order_u64(&input[84..92])?,
            state,
            order_url: urls[0],
            finalize_url: urls[1],
            certificate_url: urls[2],
            authorization_urls,
            authorization_count: count as u8,
        };
        let mut canonical = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
        let length = record.encode(&mut canonical)?;
        if canonical[..length] != *input {
            return Err(AcmedOrderRecordError::Malformed);
        }
        Ok(record)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedOrderRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.identity != config.identity
        {
            Err(AcmedOrderRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }
}

fn text_url(url: Option<&AcmeUrl>) -> &str {
    url.map(AcmeUrl::as_str).unwrap_or("")
}

fn encode_order_state(state: OrderState) -> u8 {
    match state {
        OrderState::Pending => 1,
        OrderState::Ready => 2,
        OrderState::Processing => 3,
        OrderState::Valid => 4,
        OrderState::Invalid => 5,
        OrderState::Deactivated => 6,
        OrderState::Expired => 7,
        OrderState::Revoked => 8,
    }
}

fn decode_order_state(value: u8) -> Result<OrderState, AcmedOrderRecordError> {
    Ok(match value {
        1 => OrderState::Pending,
        2 => OrderState::Ready,
        3 => OrderState::Processing,
        4 => OrderState::Valid,
        5 => OrderState::Invalid,
        6 => OrderState::Deactivated,
        7 => OrderState::Expired,
        8 => OrderState::Revoked,
        _ => return Err(AcmedOrderRecordError::Malformed),
    })
}

fn read_order_u64(input: &[u8]) -> Result<u64, AcmedOrderRecordError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| AcmedOrderRecordError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedChallengePhase {
    Selected = 1,
    Published = 2,
    Propagated = 3,
    Accepted = 4,
    CleanupPending = 5,
    Complete = 6,
    SubmissionMayHaveBeenSent = 7,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedChallengeRecord {
    pub phase: AcmedChallengePhase,
    pub authorization_index: u8,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub identity: [u8; 16],
    pub operation_id: [u8; 16],
    pub challenge_generation: u64,
    pub identifier: DnsIdentifier,
    pub authorization_url: AcmeUrl,
    pub challenge_url: AcmeUrl,
    pub token: mrml_acme::ChallengeToken,
    pub key_authorization_digest: [u8; 32],
    pub provider_record_id: [u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES],
    pub provider_record_id_length: u8,
    pub provider_binding_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedChallengeRecordError {
    InvalidState,
    OutputTooSmall,
    Malformed,
    PolicyMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedFinalizationPhase {
    RequestMayHaveBeenSent = 1,
    ResponseAuthenticated = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedFinalizationRecord {
    pub phase: AcmedFinalizationPhase,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub identity: [u8; 16],
    pub order_url_digest: [u8; 32],
    pub csr_digest: [u8; 32],
    pub key_generation: u64,
}

impl AcmedFinalizationRecord {
    pub fn object_id(&self) -> [u8; 16] {
        finalization_object_id(self.identity)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedOrderRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.identity != config.identity
            || self.key_generation != config.key_generation
        {
            Err(AcmedOrderRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedOrderRecordError> {
        if output.len() < FINALIZATION_RECORD_BYTES
            || self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.identity == [0; 16]
            || self.order_url_digest == [0; 32]
            || self.csr_digest == [0; 32]
            || self.key_generation == 0
        {
            return Err(AcmedOrderRecordError::InvalidState);
        }
        output[..FINALIZATION_RECORD_BYTES].fill(0);
        output[..8].copy_from_slice(FINALIZATION_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[16..24].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[24..32].copy_from_slice(&self.account_generation.to_be_bytes());
        output[32..40].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[40..56].copy_from_slice(&self.identity);
        output[56..88].copy_from_slice(&self.order_url_digest);
        output[88..120].copy_from_slice(&self.csr_digest);
        output[120..128].copy_from_slice(&self.key_generation.to_be_bytes());
        Ok(FINALIZATION_RECORD_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcmedOrderRecordError> {
        if input.len() != FINALIZATION_RECORD_BYTES
            || input.get(..8) != Some(FINALIZATION_RECORD_MAGIC)
            || input[9..16].iter().any(|byte| *byte != 0)
        {
            return Err(AcmedOrderRecordError::Malformed);
        }
        let phase = match input[8] {
            1 => AcmedFinalizationPhase::RequestMayHaveBeenSent,
            2 => AcmedFinalizationPhase::ResponseAuthenticated,
            _ => return Err(AcmedOrderRecordError::Malformed),
        };
        let record = Self {
            phase,
            directory_generation: read_order_u64(&input[16..24])?,
            account_generation: read_order_u64(&input[24..32])?,
            policy_generation: read_order_u64(&input[32..40])?,
            identity: input[40..56]
                .try_into()
                .map_err(|_| AcmedOrderRecordError::Malformed)?,
            order_url_digest: input[56..88]
                .try_into()
                .map_err(|_| AcmedOrderRecordError::Malformed)?,
            csr_digest: input[88..120]
                .try_into()
                .map_err(|_| AcmedOrderRecordError::Malformed)?,
            key_generation: read_order_u64(&input[120..128])?,
        };
        let mut canonical = [0u8; FINALIZATION_RECORD_BYTES];
        record.encode(&mut canonical)?;
        if canonical != input {
            return Err(AcmedOrderRecordError::Malformed);
        }
        Ok(record)
    }
}

pub fn finalization_object_id(identity: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"MRML acmed finalization object v1\0");
    digest.update(&identity);
    let digest = digest.finalize();
    let mut object = [0u8; 16];
    object.copy_from_slice(&digest[..16]);
    object
}

impl AcmedChallengeRecord {
    pub fn durable_object_id(&self) -> [u8; 16] {
        challenge_object_id(self.identity, self.authorization_index, self.identifier)
    }

    pub fn publication_receipt(
        &self,
    ) -> Result<Option<Dns01PublicationReceipt>, AcmedChallengeRecordError> {
        if self.phase == AcmedChallengePhase::Selected {
            return Ok(None);
        }
        let name = Dns01RecordName::for_identifier(self.identifier)
            .map_err(|_| AcmedChallengeRecordError::InvalidState)?;
        let value = Dns01TxtValue::from_key_authorization_digest(self.key_authorization_digest);
        let receipt = Dns01PublicationReceipt {
            operation_id: self.operation_id,
            generation: self.challenge_generation,
            identifier: self.identifier,
            key_authorization_digest: self.key_authorization_digest,
            name,
            value,
            provider_record_id: self.provider_record_id,
            provider_record_id_length: self.provider_record_id_length,
            binding_digest: self.provider_binding_digest,
        };
        let request = Dns01PublicationRequest {
            operation_id: self.operation_id,
            generation: self.challenge_generation,
            identifier: self.identifier,
            key_authorization_digest: self.key_authorization_digest,
        };
        if receipt
            .provider_record_id()
            .map_err(|_| AcmedChallengeRecordError::InvalidState)?
            .is_empty()
            || dns01_publication_binding(
                request,
                name,
                value,
                receipt
                    .provider_record_id()
                    .map_err(|_| AcmedChallengeRecordError::InvalidState)?,
            ) != receipt.binding_digest
        {
            return Err(AcmedChallengeRecordError::InvalidState);
        }
        Ok(Some(receipt))
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedChallengeRecordError> {
        let identifier = self.identifier.as_str().as_bytes();
        let authorization = self.authorization_url.as_str().as_bytes();
        let challenge = self.challenge_url.as_str().as_bytes();
        let token = self.token.as_str().as_bytes();
        let provider_length = usize::from(self.provider_record_id_length);
        let published = self.phase != AcmedChallengePhase::Selected;
        if self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.identity == [0; 16]
            || self.operation_id == [0; 16]
            || self.challenge_generation == 0
            || self.key_authorization_digest == [0; 32]
            || self.authorization_index as usize >= MAX_AUTHORIZATIONS
            || identifier.is_empty()
            || identifier.len() > u8::MAX as usize
            || authorization.len() > u16::MAX as usize
            || challenge.len() > u16::MAX as usize
            || token.is_empty()
            || token.len() > u8::MAX as usize
            || provider_length > MAX_DNS01_PROVIDER_RECORD_ID_BYTES
            || published != (provider_length != 0 && self.provider_binding_digest != [0; 32])
            || self.provider_record_id[provider_length..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(AcmedChallengeRecordError::InvalidState);
        }
        if published {
            self.publication_receipt()?;
        }
        let length = CHALLENGE_RECORD_HEADER_BYTES
            .checked_add(identifier.len())
            .and_then(|length| length.checked_add(authorization.len()))
            .and_then(|length| length.checked_add(challenge.len()))
            .and_then(|length| length.checked_add(token.len()))
            .and_then(|length| length.checked_add(provider_length))
            .ok_or(AcmedChallengeRecordError::OutputTooSmall)?;
        if output.len() < length {
            return Err(AcmedChallengeRecordError::OutputTooSmall);
        }
        output[..length].fill(0);
        output[..8].copy_from_slice(CHALLENGE_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[9] = self.authorization_index;
        output[10] = identifier.len() as u8;
        output[11] = token.len() as u8;
        output[12..14].copy_from_slice(&(authorization.len() as u16).to_be_bytes());
        output[14..16].copy_from_slice(&(challenge.len() as u16).to_be_bytes());
        output[16] = self.provider_record_id_length;
        output[18..26].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[26..34].copy_from_slice(&self.account_generation.to_be_bytes());
        output[34..42].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[42..58].copy_from_slice(&self.identity);
        output[58..74].copy_from_slice(&self.operation_id);
        output[74..82].copy_from_slice(&self.challenge_generation.to_be_bytes());
        output[82..114].copy_from_slice(&self.key_authorization_digest);
        output[114..146].copy_from_slice(&self.provider_binding_digest);
        let mut cursor = CHALLENGE_RECORD_HEADER_BYTES;
        for value in [
            identifier,
            authorization,
            challenge,
            token,
            &self.provider_record_id[..provider_length],
        ] {
            output[cursor..cursor + value.len()].copy_from_slice(value);
            cursor += value.len();
        }
        Ok(length)
    }

    pub fn decode(
        input: &[u8],
        configured_directory: &AcmeUrl,
        allow_test_http: bool,
        wildcard_allowed: bool,
    ) -> Result<Self, AcmedChallengeRecordError> {
        if input.len() < CHALLENGE_RECORD_HEADER_BYTES
            || input.get(..8) != Some(CHALLENGE_RECORD_MAGIC)
            || input[17] != 0
        {
            return Err(AcmedChallengeRecordError::Malformed);
        }
        let phase = match input[8] {
            1 => AcmedChallengePhase::Selected,
            2 => AcmedChallengePhase::Published,
            3 => AcmedChallengePhase::Propagated,
            4 => AcmedChallengePhase::Accepted,
            5 => AcmedChallengePhase::CleanupPending,
            6 => AcmedChallengePhase::Complete,
            7 => AcmedChallengePhase::SubmissionMayHaveBeenSent,
            _ => return Err(AcmedChallengeRecordError::Malformed),
        };
        let lengths = [
            usize::from(input[10]),
            usize::from(u16::from_be_bytes([input[12], input[13]])),
            usize::from(u16::from_be_bytes([input[14], input[15]])),
            usize::from(input[11]),
            usize::from(input[16]),
        ];
        if lengths
            .iter()
            .try_fold(CHALLENGE_RECORD_HEADER_BYTES, |sum, value| {
                sum.checked_add(*value)
            })
            != Some(input.len())
        {
            return Err(AcmedChallengeRecordError::Malformed);
        }
        let mut cursor = CHALLENGE_RECORD_HEADER_BYTES;
        let mut next = |length: usize| -> Result<&[u8], AcmedChallengeRecordError> {
            let end = cursor
                .checked_add(length)
                .ok_or(AcmedChallengeRecordError::Malformed)?;
            let value = input
                .get(cursor..end)
                .ok_or(AcmedChallengeRecordError::Malformed)?;
            cursor = end;
            Ok(value)
        };
        let identifier = DnsIdentifier::parse(
            core::str::from_utf8(next(lengths[0])?)
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
            wildcard_allowed,
        )
        .map_err(|_| AcmedChallengeRecordError::Malformed)?;
        let authorization_url =
            decode_challenge_url(next(lengths[1])?, configured_directory, allow_test_http)?;
        let challenge_url =
            decode_challenge_url(next(lengths[2])?, configured_directory, allow_test_http)?;
        let token = mrml_acme::ChallengeToken::parse(
            core::str::from_utf8(next(lengths[3])?)
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
        )
        .map_err(|_| AcmedChallengeRecordError::Malformed)?;
        let provider = next(lengths[4])?;
        let mut provider_record_id = [0u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES];
        provider_record_id[..provider.len()].copy_from_slice(provider);
        let record = Self {
            phase,
            authorization_index: input[9],
            directory_generation: read_challenge_u64(&input[18..26])?,
            account_generation: read_challenge_u64(&input[26..34])?,
            policy_generation: read_challenge_u64(&input[34..42])?,
            identity: input[42..58]
                .try_into()
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
            operation_id: input[58..74]
                .try_into()
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
            challenge_generation: read_challenge_u64(&input[74..82])?,
            identifier,
            authorization_url,
            challenge_url,
            token,
            key_authorization_digest: input[82..114]
                .try_into()
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
            provider_record_id,
            provider_record_id_length: input[16],
            provider_binding_digest: input[114..146]
                .try_into()
                .map_err(|_| AcmedChallengeRecordError::Malformed)?,
        };
        let mut canonical = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
        let length = record.encode(&mut canonical)?;
        if canonical[..length] != *input {
            return Err(AcmedChallengeRecordError::Malformed);
        }
        Ok(record)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedChallengeRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.identity != config.identity
            || usize::from(self.authorization_index) >= usize::from(config.identifier_count)
            || config.identifiers[usize::from(self.authorization_index)] != Some(self.identifier)
        {
            Err(AcmedChallengeRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }
}

pub fn challenge_object_id(
    identity: [u8; 16],
    authorization_index: u8,
    identifier: DnsIdentifier,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"MRML acmed DNS-01 challenge object v1\0");
    digest.update(&identity);
    digest.update(&[authorization_index]);
    digest.update(identifier.as_str().as_bytes());
    let digest = digest.finalize();
    let mut object = [0u8; 16];
    object.copy_from_slice(&digest[..16]);
    object
}

fn decode_challenge_url(
    input: &[u8],
    configured_directory: &AcmeUrl,
    allow_test_http: bool,
) -> Result<AcmeUrl, AcmedChallengeRecordError> {
    let text = core::str::from_utf8(input).map_err(|_| AcmedChallengeRecordError::Malformed)?;
    let url =
        AcmeUrl::parse(text, allow_test_http).map_err(|_| AcmedChallengeRecordError::Malformed)?;
    url.require_origin(configured_directory.origin())
        .map_err(|_| AcmedChallengeRecordError::PolicyMismatch)?;
    Ok(url)
}

fn read_challenge_u64(input: &[u8]) -> Result<u64, AcmedChallengeRecordError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| AcmedChallengeRecordError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeDirectoryClass {
    LocalTest,
    PublicStaging,
    PublicProduction,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedConfig {
    pub directory_url: AcmeUrl,
    pub directory_generation: u64,
    pub directory_class: AcmeDirectoryClass,
    pub approved_terms_url: Option<AcmeUrl>,
    pub approved_terms_content_digest: Option<[u8; 32]>,
    pub zone_id: [u8; 32],
    pub zone: DnsIdentifier,
    pub identity: [u8; 16],
    pub account_identity: [u8; 16],
    pub account_generation: u64,
    pub key_generation: u64,
    pub policy_generation: u64,
    pub certificate_profile: CertificateProfile,
    pub order_lifetime_seconds: u64,
    pub order_retry_limit: u8,
    pub authoritative_dns_ipv4: [u8; 4],
    pub authoritative_dns_port: u16,
    pub recursive_dns_ipv4: [u8; 4],
    pub recursive_dns_port: u16,
    pub propagation_attempts: u8,
    pub propagation_interval_seconds: u64,
    pub propagation_timeout_seconds: u64,
    pub identifiers: [Option<DnsIdentifier>; MAX_CSR_IDENTIFIERS],
    pub identifier_count: u8,
    pub identifier_set_digest: [u8; 32],
    pub wildcard_enabled: bool,
    pub poll_interval_seconds: u64,
    pub global_concurrency: u8,
    pub per_identity_concurrency: u8,
    pub renewal_policy: RenewalPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedConfigError {
    Oversized,
    Malformed,
    UnknownField,
    MissingField,
    InvalidDirectory,
    InvalidTermsApproval,
    ProductionNotEnabled,
    InvalidZone,
    InvalidIdentity,
    InvalidBounds,
}

impl AcmedConfig {
    pub fn terms_approval(
        &self,
        directory: &AcmeDirectory,
    ) -> Result<Option<OwnerTermsApproval>, AcmedConfigError> {
        match (
            directory.terms_of_service.as_ref(),
            self.approved_terms_url.as_ref(),
            self.approved_terms_content_digest,
        ) {
            (None, None, None) => Ok(None),
            (Some(advertised), Some(approved), Some(digest)) if advertised == approved => {
                OwnerTermsApproval::from_content_digest(directory.generation, approved, digest)
                    .map(Some)
                    .map_err(|_| AcmedConfigError::InvalidTermsApproval)
            }
            _ => Err(AcmedConfigError::InvalidTermsApproval),
        }
    }
}

pub fn parse_acmed_config(source: &str) -> Result<AcmedConfig, AcmedConfigError> {
    if source.is_empty() || source.len() > MAX_ACMED_CONFIG_BYTES {
        return Err(AcmedConfigError::Oversized);
    }
    let value = mrml_json::parse(source).map_err(|_| AcmedConfigError::Malformed)?;
    let object = value.as_object().ok_or(AcmedConfigError::Malformed)?;
    const FIELDS: [&str; 37] = [
        "directory_url",
        "directory_generation",
        "directory_class",
        "production_enabled",
        "terms_of_service_url",
        "terms_content_sha256",
        "dns_provider",
        "zone_id",
        "zone",
        "identity",
        "account_identity",
        "account_generation",
        "key_generation",
        "policy_generation",
        "certificate_profile",
        "order_lifetime_seconds",
        "order_retry_limit",
        "authoritative_dns_ipv4",
        "authoritative_dns_port",
        "recursive_dns_ipv4",
        "recursive_dns_port",
        "propagation_attempts",
        "propagation_interval_seconds",
        "propagation_timeout_seconds",
        "identifiers",
        "wildcard_enabled",
        "poll_interval_seconds",
        "global_concurrency",
        "renewal_elapsed_numerator",
        "renewal_elapsed_denominator",
        "minimum_renewal_lead_seconds",
        "warning_lead_seconds",
        "critical_lead_seconds",
        "initial_backoff_seconds",
        "maximum_backoff_seconds",
        "ari_requery_min_seconds",
        "ari_requery_max_seconds",
    ];
    if object
        .iter()
        .any(|(key, _)| !FIELDS.contains(&key.as_str()))
    {
        return Err(AcmedConfigError::UnknownField);
    }
    if object.len() != FIELDS.len() {
        return Err(AcmedConfigError::MissingField);
    }
    let directory_class = match text(&value, "directory_class")? {
        "local-test" => AcmeDirectoryClass::LocalTest,
        "public-staging" => AcmeDirectoryClass::PublicStaging,
        "public-production" => AcmeDirectoryClass::PublicProduction,
        _ => return Err(AcmedConfigError::InvalidDirectory),
    };
    let production_enabled = value
        .get("production_enabled")
        .and_then(Value::as_bool)
        .ok_or(AcmedConfigError::MissingField)?;
    if (directory_class == AcmeDirectoryClass::PublicProduction) != production_enabled {
        return Err(AcmedConfigError::ProductionNotEnabled);
    }
    if text(&value, "dns_provider")? != "cloudflare" {
        return Err(AcmedConfigError::InvalidZone);
    }
    let directory_url = AcmeUrl::parse(
        text(&value, "directory_url")?,
        directory_class == AcmeDirectoryClass::LocalTest,
    )
    .map_err(|_| AcmedConfigError::InvalidDirectory)?;
    let directory_generation = number(&value, "directory_generation")?;
    if directory_generation == 0 {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let approved_terms_url = optional_text(&value, "terms_of_service_url")?
        .map(|url| AcmeUrl::parse(url, directory_class == AcmeDirectoryClass::LocalTest))
        .transpose()
        .map_err(|_| AcmedConfigError::InvalidTermsApproval)?;
    let approved_terms_content_digest = optional_text(&value, "terms_content_sha256")?
        .map(parse_digest)
        .transpose()?;
    if approved_terms_url.is_some() != approved_terms_content_digest.is_some() {
        return Err(AcmedConfigError::InvalidTermsApproval);
    }
    let zone_id_text = text(&value, "zone_id")?;
    if !valid_hex(zone_id_text, 32) {
        return Err(AcmedConfigError::InvalidZone);
    }
    let mut zone_id = [0u8; 32];
    zone_id.copy_from_slice(zone_id_text.as_bytes());
    let zone = DnsIdentifier::parse(text(&value, "zone")?, false)
        .map_err(|_| AcmedConfigError::InvalidZone)?;
    if zone.is_wildcard() {
        return Err(AcmedConfigError::InvalidZone);
    }
    let identity = parse_identity(text(&value, "identity")?)?;
    let account_identity = parse_identity(text(&value, "account_identity")?)?;
    if identity == account_identity {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let account_generation = number(&value, "account_generation")?;
    let key_generation = number(&value, "key_generation")?;
    let policy_generation = number(&value, "policy_generation")?;
    if account_generation == 0 || key_generation == 0 || policy_generation == 0 {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let certificate_profile =
        CertificateProfile::parse(text(&value, "certificate_profile")?, directory_generation)
            .map_err(|_| AcmedConfigError::InvalidBounds)?;
    let order_lifetime_seconds = number(&value, "order_lifetime_seconds")?;
    let order_retry_limit = u8::try_from(number(&value, "order_retry_limit")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    if !(300..=86_400).contains(&order_lifetime_seconds) || !(1..=16).contains(&order_retry_limit) {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let authoritative_dns_ipv4 = parse_ipv4(text(&value, "authoritative_dns_ipv4")?)?;
    let authoritative_dns_port = u16::try_from(number(&value, "authoritative_dns_port")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    let recursive_dns_ipv4 = parse_ipv4(text(&value, "recursive_dns_ipv4")?)?;
    let recursive_dns_port = u16::try_from(number(&value, "recursive_dns_port")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    let propagation_attempts = u8::try_from(number(&value, "propagation_attempts")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    let propagation_interval_seconds = number(&value, "propagation_interval_seconds")?;
    let propagation_timeout_seconds = number(&value, "propagation_timeout_seconds")?;
    if authoritative_dns_port == 0
        || recursive_dns_port == 0
        || authoritative_dns_ipv4 == [0; 4]
        || recursive_dns_ipv4 == [0; 4]
        || authoritative_dns_ipv4 == recursive_dns_ipv4
        || !(1..=32).contains(&propagation_attempts)
        || !(1..=60).contains(&propagation_interval_seconds)
        || !(30..=3_600).contains(&propagation_timeout_seconds)
        || propagation_interval_seconds
            .checked_mul(u64::from(propagation_attempts))
            .is_none_or(|span| span > propagation_timeout_seconds)
    {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let wildcard_enabled = value
        .get("wildcard_enabled")
        .and_then(Value::as_bool)
        .ok_or(AcmedConfigError::MissingField)?;
    let list = value
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or(AcmedConfigError::MissingField)?;
    if list.is_empty() || list.len() > MAX_CSR_IDENTIFIERS {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let mut identifiers = [None; MAX_CSR_IDENTIFIERS];
    let mut previous: Option<DnsIdentifier> = None;
    for (index, item) in list.iter().enumerate() {
        let identifier = DnsIdentifier::parse(
            item.as_str().ok_or(AcmedConfigError::InvalidIdentity)?,
            wildcard_enabled,
        )
        .map_err(|_| AcmedConfigError::InvalidIdentity)?;
        if previous.is_some_and(|prior| prior.as_str() >= identifier.as_str()) {
            return Err(AcmedConfigError::InvalidIdentity);
        }
        identifiers[index] = Some(identifier);
        previous = Some(identifier);
    }
    let identifier_set_digest = certd_identifier_set_digest(&identifiers[..list.len()]);
    let poll_interval_seconds = number(&value, "poll_interval_seconds")?;
    let global_concurrency = u8::try_from(number(&value, "global_concurrency")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    if !(5..=3_600).contains(&poll_interval_seconds) || !(1..=8).contains(&global_concurrency) {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let renewal_policy = RenewalPolicy {
        generation: policy_generation,
        fallback_elapsed_numerator: u32::try_from(number(&value, "renewal_elapsed_numerator")?)
            .map_err(|_| AcmedConfigError::InvalidBounds)?,
        fallback_elapsed_denominator: u32::try_from(number(&value, "renewal_elapsed_denominator")?)
            .map_err(|_| AcmedConfigError::InvalidBounds)?,
        minimum_renewal_lead_seconds: number(&value, "minimum_renewal_lead_seconds")?,
        warning_lead_seconds: number(&value, "warning_lead_seconds")?,
        critical_lead_seconds: number(&value, "critical_lead_seconds")?,
        initial_backoff_seconds: number(&value, "initial_backoff_seconds")?,
        maximum_backoff_seconds: number(&value, "maximum_backoff_seconds")?,
        ari_requery_min_seconds: number(&value, "ari_requery_min_seconds")?,
        ari_requery_max_seconds: number(&value, "ari_requery_max_seconds")?,
    };
    if renewal_policy.fallback_elapsed_denominator == 0
        || renewal_policy.fallback_elapsed_numerator >= renewal_policy.fallback_elapsed_denominator
        || renewal_policy.minimum_renewal_lead_seconds < 86_400
        || renewal_policy.warning_lead_seconds <= renewal_policy.critical_lead_seconds
        || renewal_policy.critical_lead_seconds < 3_600
        || renewal_policy.initial_backoff_seconds == 0
        || renewal_policy.maximum_backoff_seconds < renewal_policy.initial_backoff_seconds
        || renewal_policy.maximum_backoff_seconds > 86_400
        || renewal_policy.ari_requery_min_seconds == 0
        || renewal_policy.ari_requery_max_seconds < renewal_policy.ari_requery_min_seconds
        || renewal_policy.ari_requery_max_seconds > 86_400
    {
        return Err(AcmedConfigError::InvalidBounds);
    }
    Ok(AcmedConfig {
        directory_url,
        directory_generation,
        directory_class,
        approved_terms_url,
        approved_terms_content_digest,
        zone_id,
        zone,
        identity,
        account_identity,
        account_generation,
        key_generation,
        policy_generation,
        certificate_profile,
        order_lifetime_seconds,
        order_retry_limit,
        authoritative_dns_ipv4,
        authoritative_dns_port,
        recursive_dns_ipv4,
        recursive_dns_port,
        propagation_attempts,
        propagation_interval_seconds,
        propagation_timeout_seconds,
        identifiers,
        identifier_count: list.len() as u8,
        identifier_set_digest,
        wildcard_enabled,
        poll_interval_seconds,
        global_concurrency,
        per_identity_concurrency: 1,
        renewal_policy,
    })
}

fn parse_identity(value: &str) -> Result<[u8; 16], AcmedConfigError> {
    if !valid_hex(value, 32) {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let mut identity = [0u8; 16];
    for (index, output) in identity.iter_mut().enumerate() {
        *output = decode_hex(&value.as_bytes()[index * 2..index * 2 + 2])?;
    }
    if identity == [0; 16] {
        Err(AcmedConfigError::InvalidIdentity)
    } else {
        Ok(identity)
    }
}

fn parse_ipv4(value: &str) -> Result<[u8; 4], AcmedConfigError> {
    let mut address = [0u8; 4];
    let mut parts = value.split('.');
    for octet in &mut address {
        let part = parts.next().ok_or(AcmedConfigError::InvalidBounds)?;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(AcmedConfigError::InvalidBounds);
        }
        *octet = part
            .parse::<u8>()
            .map_err(|_| AcmedConfigError::InvalidBounds)?;
    }
    if parts.next().is_some() {
        return Err(AcmedConfigError::InvalidBounds);
    }
    Ok(address)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, AcmedConfigError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(AcmedConfigError::MissingField)
}

fn number(value: &Value, key: &str) -> Result<u64, AcmedConfigError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(AcmedConfigError::MissingField)
}

fn optional_text<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, AcmedConfigError> {
    let value = value.get(key).ok_or(AcmedConfigError::MissingField)?;
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(Some)
        .ok_or(AcmedConfigError::InvalidTermsApproval)
}

fn parse_digest(value: &str) -> Result<[u8; 32], AcmedConfigError> {
    if !valid_hex(value, 64) {
        return Err(AcmedConfigError::InvalidTermsApproval);
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = decode_hex(&value.as_bytes()[index * 2..index * 2 + 2])?;
    }
    if digest == [0; 32] {
        Err(AcmedConfigError::InvalidTermsApproval)
    } else {
        Ok(digest)
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_hex(value: &[u8]) -> Result<u8, AcmedConfigError> {
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    Ok(
        nibble(value[0]).ok_or(AcmedConfigError::InvalidIdentity)? << 4
            | nibble(value[1]).ok_or(AcmedConfigError::InvalidIdentity)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_certificate::{
        DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
        HmacSha256DurableAuthenticator, MAX_DURABLE_RECORD_BYTES,
    };

    const STAGING: &str = r#"{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","directory_generation":1,"directory_class":"public-staging","production_enabled":false,"terms_of_service_url":"https://letsencrypt.org/documents/approved.pdf","terms_content_sha256":"1111111111111111111111111111111111111111111111111111111111111111","dns_provider":"cloudflare","zone_id":"0123456789abcdef0123456789abcdef","zone":"example.com","identity":"11111111111111111111111111111111","account_identity":"22222222222222222222222222222222","account_generation":1,"key_generation":1,"policy_generation":1,"certificate_profile":"classic","order_lifetime_seconds":3600,"order_retry_limit":6,"authoritative_dns_ipv4":"192.0.2.53","authoritative_dns_port":53,"recursive_dns_ipv4":"198.51.100.53","recursive_dns_port":53,"propagation_attempts":12,"propagation_interval_seconds":5,"propagation_timeout_seconds":300,"identifiers":["example.com","www.example.com"],"wildcard_enabled":false,"poll_interval_seconds":30,"global_concurrency":2,"renewal_elapsed_numerator":2,"renewal_elapsed_denominator":3,"minimum_renewal_lead_seconds":604800,"warning_lead_seconds":1209600,"critical_lead_seconds":259200,"initial_backoff_seconds":60,"maximum_backoff_seconds":21600,"ari_requery_min_seconds":21600,"ari_requery_max_seconds":43200}"#;

    #[test]
    fn account_record_round_trips_only_exact_policy_bound_states() {
        let config = parse_acmed_config(STAGING).unwrap();
        let pending = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            policy_generation: config.policy_generation,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: None,
        };
        let mut encoded = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = pending.encode(&mut encoded).unwrap();
        let decoded =
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false).unwrap();
        assert!(decoded == pending);
        decoded.require_policy(&config).unwrap();

        let active = AcmedAccountRecord {
            phase: AcmedAccountPhase::Active,
            account_url: Some(
                AcmeUrl::parse("https://acme-staging-v02.api.letsencrypt.org/acct/1", false)
                    .unwrap(),
            ),
            ..pending
        };
        let length = active.encode(&mut encoded).unwrap();
        assert!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false).unwrap()
                == active
        );
        let rollover = AcmedAccountRecord {
            phase: AcmedAccountPhase::RolloverMayHaveBeenSent,
            account_generation: 2,
            ..active
        };
        let length = rollover.encode(&mut encoded).unwrap();
        assert!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false).unwrap()
                == rollover
        );
        encoded[9] = 1;
        assert!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false,).is_err()
        );
    }

    #[test]
    fn account_record_rejects_cross_origin_and_phase_url_confusion() {
        let config = parse_acmed_config(STAGING).unwrap();
        let record = AcmedAccountRecord {
            phase: AcmedAccountPhase::Active,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: Some(AcmeUrl::parse("https://other.example/acct/1", false).unwrap()),
        };
        let mut encoded = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = record.encode(&mut encoded).unwrap();
        assert!(matches!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false),
            Err(AcmedAccountRecordError::PolicyMismatch)
        ));
        let confused = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            ..record
        };
        assert!(matches!(
            confused.encode(&mut encoded),
            Err(AcmedAccountRecordError::InvalidState)
        ));
    }

    #[test]
    fn account_record_requires_keyed_durable_authentication() {
        let config = parse_acmed_config(STAGING).unwrap();
        let account = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: None,
        };
        let mut payload = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let payload_length = account.encode(&mut payload).unwrap();
        let mut writer = HmacSha256DurableAuthenticator::new([0x51; 32]);
        let durable = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Account,
            DurableObjectId(config.account_identity),
            0,
            &payload[..payload_length],
            &mut writer,
        )
        .unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let length = durable.encode(&mut encoded).unwrap();
        let mut correct = HmacSha256DurableAuthenticator::new([0x51; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut correct).is_ok());
        let mut wrong = HmacSha256DurableAuthenticator::new([0x52; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut wrong).is_err());
        encoded[length - 1] ^= 1;
        let mut correct = HmacSha256DurableAuthenticator::new([0x51; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut correct).is_err());
    }

    #[test]
    fn channel_request_reservations_advance_across_restart_without_overlap() {
        let identity = [7; 16];
        let mut first = AcmedChannelRequestCounter::new(identity).unwrap();
        let reserved = first.reserve().unwrap();
        assert_eq!(reserved.next, 1);
        assert_eq!(reserved.last, CHANNEL_REQUEST_RESERVATION);
        let mut encoded = [0u8; 32];
        first.encode(&mut encoded).unwrap();
        let mut restarted = AcmedChannelRequestCounter::decode(&encoded).unwrap();
        let after_restart = restarted.reserve().unwrap();
        assert_eq!(after_restart.next, reserved.last + 1);
        assert!(after_restart.next > reserved.last);
        encoded[0] ^= 1;
        assert!(AcmedChannelRequestCounter::decode(&encoded).is_err());
    }

    #[test]
    fn order_record_round_trips_pending_and_created_resource_sets() {
        let config = parse_acmed_config(STAGING).unwrap();
        let pending = AcmedOrderRecord {
            phase: AcmedOrderPhase::RequestMayHaveBeenSent,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            identity: config.identity,
            request_digest: [8; 32],
            deadline_unix: 10_000,
            state: None,
            order_url: None,
            finalize_url: None,
            certificate_url: None,
            authorization_urls: [None; MAX_AUTHORIZATIONS],
            authorization_count: 0,
        };
        let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
        let length = pending.encode(&mut encoded).unwrap();
        let decoded =
            AcmedOrderRecord::decode(&encoded[..length], &config.directory_url, false).unwrap();
        assert!(decoded == pending);
        decoded.require_policy(&config).unwrap();

        let mut authorizations = [None; MAX_AUTHORIZATIONS];
        authorizations[0] = Some(
            AcmeUrl::parse(
                "https://acme-staging-v02.api.letsencrypt.org/authz/1",
                false,
            )
            .unwrap(),
        );
        authorizations[1] = Some(
            AcmeUrl::parse(
                "https://acme-staging-v02.api.letsencrypt.org/authz/2",
                false,
            )
            .unwrap(),
        );
        let created = AcmedOrderRecord {
            phase: AcmedOrderPhase::Created,
            state: Some(OrderState::Pending),
            order_url: Some(
                AcmeUrl::parse(
                    "https://acme-staging-v02.api.letsencrypt.org/order/1",
                    false,
                )
                .unwrap(),
            ),
            finalize_url: Some(
                AcmeUrl::parse(
                    "https://acme-staging-v02.api.letsencrypt.org/finalize/1",
                    false,
                )
                .unwrap(),
            ),
            authorization_urls: authorizations,
            authorization_count: 2,
            ..pending
        };
        let length = created.encode(&mut encoded).unwrap();
        assert!(
            AcmedOrderRecord::decode(&encoded[..length], &config.directory_url, false).unwrap()
                == created
        );
        let mut writer = HmacSha256DurableAuthenticator::new([0x61; 32]);
        let durable = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Order,
            DurableObjectId(config.identity),
            0,
            &encoded[..length],
            &mut writer,
        )
        .unwrap();
        let mut authenticated = [0u8; MAX_DURABLE_RECORD_BYTES];
        let authenticated_length = durable.encode(&mut authenticated).unwrap();
        let mut wrong = HmacSha256DurableAuthenticator::new([0x62; 32]);
        assert!(DurableRecord::decode(&authenticated[..authenticated_length], &mut wrong).is_err());
        encoded[11] = 1;
        assert!(
            AcmedOrderRecord::decode(&encoded[..length], &config.directory_url, false,).is_err()
        );
    }

    #[test]
    fn order_record_rejects_cross_origin_and_partial_created_state() {
        let config = parse_acmed_config(STAGING).unwrap();
        let partial = AcmedOrderRecord {
            phase: AcmedOrderPhase::Created,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            identity: config.identity,
            request_digest: [8; 32],
            deadline_unix: 10_000,
            state: Some(OrderState::Pending),
            order_url: Some(AcmeUrl::parse("https://other.example/order/1", false).unwrap()),
            finalize_url: None,
            certificate_url: None,
            authorization_urls: [None; MAX_AUTHORIZATIONS],
            authorization_count: 0,
        };
        let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
        assert!(matches!(
            partial.encode(&mut encoded),
            Err(AcmedOrderRecordError::InvalidState)
        ));
        let complete = AcmedOrderRecord {
            finalize_url: Some(AcmeUrl::parse("https://other.example/finalize/1", false).unwrap()),
            ..partial
        };
        let length = complete.encode(&mut encoded).unwrap();
        assert!(matches!(
            AcmedOrderRecord::decode(&encoded[..length], &config.directory_url, false),
            Err(AcmedOrderRecordError::PolicyMismatch)
        ));
    }

    #[test]
    fn challenge_record_round_trips_selected_and_exact_publication_receipt() {
        let config = parse_acmed_config(STAGING).unwrap();
        let identifier = config.identifiers[0].unwrap();
        let selected = AcmedChallengeRecord {
            phase: AcmedChallengePhase::Selected,
            authorization_index: 0,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            identity: config.identity,
            operation_id: [9; 16],
            challenge_generation: 1,
            identifier,
            authorization_url: AcmeUrl::parse(
                "https://acme-staging-v02.api.letsencrypt.org/authz/1",
                false,
            )
            .unwrap(),
            challenge_url: AcmeUrl::parse(
                "https://acme-staging-v02.api.letsencrypt.org/challenge/1",
                false,
            )
            .unwrap(),
            token: mrml_acme::ChallengeToken::parse("token-1").unwrap(),
            key_authorization_digest: [0x21; 32],
            provider_record_id: [0; MAX_DNS01_PROVIDER_RECORD_ID_BYTES],
            provider_record_id_length: 0,
            provider_binding_digest: [0; 32],
        };
        selected.require_policy(&config).unwrap();
        assert!(selected.publication_receipt().unwrap().is_none());
        let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
        let length = selected.encode(&mut encoded).unwrap();
        assert!(
            AcmedChallengeRecord::decode(&encoded[..length], &config.directory_url, false, false,)
                .unwrap()
                == selected
        );

        let request = Dns01PublicationRequest {
            operation_id: selected.operation_id,
            generation: selected.challenge_generation,
            identifier,
            key_authorization_digest: selected.key_authorization_digest,
        };
        let name = Dns01RecordName::for_identifier(identifier).unwrap();
        let value = Dns01TxtValue::from_key_authorization_digest(selected.key_authorization_digest);
        let provider_id = b"0123456789abcdef0123456789abcdef";
        let mut provider_record_id = [0u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES];
        provider_record_id[..provider_id.len()].copy_from_slice(provider_id);
        let published = AcmedChallengeRecord {
            phase: AcmedChallengePhase::Published,
            provider_record_id,
            provider_record_id_length: provider_id.len() as u8,
            provider_binding_digest: dns01_publication_binding(
                request,
                name,
                value,
                core::str::from_utf8(provider_id).unwrap(),
            ),
            ..selected
        };
        let length = published.encode(&mut encoded).unwrap();
        let decoded =
            AcmedChallengeRecord::decode(&encoded[..length], &config.directory_url, false, false)
                .unwrap();
        assert!(decoded == published);
        assert_eq!(
            decoded
                .publication_receipt()
                .unwrap()
                .unwrap()
                .provider_record_id()
                .unwrap(),
            core::str::from_utf8(provider_id).unwrap()
        );
        let uncertain = AcmedChallengeRecord {
            phase: AcmedChallengePhase::SubmissionMayHaveBeenSent,
            ..published
        };
        let length = uncertain.encode(&mut encoded).unwrap();
        assert!(
            AcmedChallengeRecord::decode(&encoded[..length], &config.directory_url, false, false)
                .unwrap()
                == uncertain
        );
    }

    #[test]
    fn challenge_objects_are_domain_separated_and_mutation_fails_closed() {
        let config = parse_acmed_config(STAGING).unwrap();
        let first = config.identifiers[0].unwrap();
        let second = config.identifiers[1].unwrap();
        assert_ne!(
            challenge_object_id(config.identity, 0, first),
            challenge_object_id(config.identity, 1, second)
        );
        assert_ne!(
            challenge_object_id(config.identity, 0, first),
            config.identity
        );
    }

    #[test]
    fn finalization_record_binds_csr_order_key_and_policy_exactly() {
        let config = parse_acmed_config(STAGING).unwrap();
        let record = AcmedFinalizationRecord {
            phase: AcmedFinalizationPhase::RequestMayHaveBeenSent,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            policy_generation: config.policy_generation,
            identity: config.identity,
            order_url_digest: [0x31; 32],
            csr_digest: [0x41; 32],
            key_generation: config.key_generation,
        };
        record.require_policy(&config).unwrap();
        assert_ne!(record.object_id(), config.identity);
        let mut encoded = [0u8; FINALIZATION_RECORD_BYTES];
        let length = record.encode(&mut encoded).unwrap();
        assert_eq!(length, FINALIZATION_RECORD_BYTES);
        assert!(AcmedFinalizationRecord::decode(&encoded).unwrap() == record);
        encoded[90] ^= 1;
        assert!(AcmedFinalizationRecord::decode(&encoded).unwrap() != record);
        encoded[9] = 1;
        assert!(AcmedFinalizationRecord::decode(&encoded).is_err());
    }

    #[test]
    fn revocation_record_preserves_uncertainty_and_exact_terminal_receipt() {
        let config = parse_acmed_config(STAGING).unwrap();
        let prepared = AcmedRevocationRecord {
            phase: AcmedRevocationPhase::Prepared,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            policy_generation: config.policy_generation,
            identity: config.identity,
            identity_generation: 7,
            revocation_generation: 2,
            certificate_id: mrml_acme::AriCertificateId::parse("a2V5.aWQ").unwrap(),
            chain_digest: [0x51; 32],
            reason: 1,
            authorization_digest: [0x61; 32],
            transaction_digest: [0; 32],
            revoked_at_unix: 0,
        };
        prepared.require_policy(&config).unwrap();
        let mut encoded = [0u8; REVOCATION_RECORD_BYTES];
        assert_eq!(
            prepared.encode(&mut encoded).unwrap(),
            REVOCATION_RECORD_BYTES
        );
        assert!(AcmedRevocationRecord::decode(&encoded).unwrap() == prepared);

        let uncertain = AcmedRevocationRecord {
            phase: AcmedRevocationPhase::SubmissionMayHaveBeenSent,
            ..prepared
        };
        uncertain.encode(&mut encoded).unwrap();
        assert!(AcmedRevocationRecord::decode(&encoded).unwrap() == uncertain);

        let revoked = AcmedRevocationRecord {
            phase: AcmedRevocationPhase::Revoked,
            transaction_digest: [0x71; 32],
            revoked_at_unix: 9,
            ..uncertain
        };
        revoked.encode(&mut encoded).unwrap();
        assert!(AcmedRevocationRecord::decode(&encoded).unwrap() == revoked);
        encoded[9] = 2;
        assert!(AcmedRevocationRecord::decode(&encoded).is_err());
        encoded[9] = 1;
        encoded[220] = 1;
        assert!(AcmedRevocationRecord::decode(&encoded).is_err());
    }

    #[test]
    fn staging_configuration_is_exact_and_bounded() {
        let config = parse_acmed_config(STAGING).unwrap();
        assert_eq!(config.directory_class, AcmeDirectoryClass::PublicStaging);
        assert_eq!(
            config.directory_url.origin().host,
            "acme-staging-v02.api.letsencrypt.org"
        );
        assert_eq!(config.per_identity_concurrency, 1);
        assert_eq!(config.identifier_count, 2);
        assert_eq!(config.certificate_profile.name(), "classic");
        assert_eq!(config.order_lifetime_seconds, 3_600);
        assert_eq!(config.order_retry_limit, 6);
        assert_eq!(config.authoritative_dns_ipv4, [192, 0, 2, 53]);
        assert_eq!(config.recursive_dns_ipv4, [198, 51, 100, 53]);
        assert_eq!(config.propagation_attempts, 12);
        assert_eq!(config.propagation_interval_seconds, 5);
        assert_eq!(config.propagation_timeout_seconds, 300);
        assert_ne!(config.identifier_set_digest, [0; 32]);
        assert!(config.approved_terms_url.is_some());
        assert_eq!(config.approved_terms_content_digest, Some([0x11; 32]));
        let directory = AcmeDirectory::parse(
            r#"{"newNonce":"https://acme-staging-v02.api.letsencrypt.org/nonce","newAccount":"https://acme-staging-v02.api.letsencrypt.org/account","newOrder":"https://acme-staging-v02.api.letsencrypt.org/order","revokeCert":"https://acme-staging-v02.api.letsencrypt.org/revoke","keyChange":"https://acme-staging-v02.api.letsencrypt.org/key-change","meta":{"termsOfService":"https://letsencrypt.org/documents/approved.pdf"}}"#,
            &config.directory_url,
            config.directory_generation,
        )
        .unwrap();
        assert!(config.terms_approval(&directory).unwrap().is_some());
        let changed = AcmeDirectory::parse(
            r#"{"newNonce":"https://acme-staging-v02.api.letsencrypt.org/nonce","newAccount":"https://acme-staging-v02.api.letsencrypt.org/account","newOrder":"https://acme-staging-v02.api.letsencrypt.org/order","revokeCert":"https://acme-staging-v02.api.letsencrypt.org/revoke","keyChange":"https://acme-staging-v02.api.letsencrypt.org/key-change","meta":{"termsOfService":"https://letsencrypt.org/documents/changed.pdf"}}"#,
            &config.directory_url,
            config.directory_generation,
        )
        .unwrap();
        assert!(matches!(
            config.terms_approval(&changed),
            Err(AcmedConfigError::InvalidTermsApproval)
        ));
    }

    #[test]
    fn production_requires_exact_explicit_enablement() {
        let production = STAGING
            .replace("public-staging", "public-production")
            .replace("production_enabled\":false", "production_enabled\":true");
        assert!(parse_acmed_config(&production).is_ok());
        let disabled =
            production.replace("production_enabled\":true", "production_enabled\":false");
        assert!(matches!(
            parse_acmed_config(&disabled),
            Err(AcmedConfigError::ProductionNotEnabled)
        ));
    }

    #[test]
    fn unknown_fields_invalid_ids_and_unsafe_bounds_fail_closed() {
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("}", ",\"extra\":1}")),
            Err(AcmedConfigError::UnknownField)
        ));
        assert!(matches!(
            parse_acmed_config(
                &STAGING.replace("poll_interval_seconds\":30", "poll_interval_seconds\":0")
            ),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("order_retry_limit\":6", "order_retry_limit\":0")),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "renewal_elapsed_numerator\":2",
                "renewal_elapsed_numerator\":3"
            )),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "critical_lead_seconds\":259200",
                "critical_lead_seconds\":1209600"
            )),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "maximum_backoff_seconds\":21600",
                "maximum_backoff_seconds\":0"
            )),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("192.0.2.53", "192.00.2.53")),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("198.51.100.53", "192.0.2.53")),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "propagation_timeout_seconds\":300",
                "propagation_timeout_seconds\":30"
            )),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("0123456789abcdef", "0123456789ABCDEF")),
            Err(AcmedConfigError::InvalidZone)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "\"terms_content_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\"",
                "\"terms_content_sha256\":null"
            )),
            Err(AcmedConfigError::InvalidTermsApproval)
        ));
    }
}
