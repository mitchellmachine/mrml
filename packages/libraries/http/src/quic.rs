use mrml_crypto::{
    aes128_encrypt_block, aes128_gcm_open, aes128_gcm_seal, hkdf_expand_label, hkdf_extract,
};
use mrml_runtime::Vector;

const V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const MAX_DATAGRAM: usize = 65_527;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    const fn initial_type(self) -> u8 {
        match self {
            Self::V1 => 0xc0,
            Self::V2 => 0xd0,
        }
    }

    const fn handshake_type(self) -> u8 {
        match self {
            Self::V1 => 0xe0,
            Self::V2 => 0xf0,
        }
    }

    const fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &V1_INITIAL_SALT,
            Self::V2 => &V2_INITIAL_SALT,
        }
    }

    const fn key_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic key",
            Self::V2 => b"quicv2 key",
        }
    }

    const fn iv_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic iv",
            Self::V2 => b"quicv2 iv",
        }
    }

    const fn hp_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic hp",
            Self::V2 => b"quicv2 hp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicError {
    Truncated,
    InvalidInteger,
    InvalidPacket,
    InvalidFrame,
    Crypto,
    Allocation,
    Limit,
    FlowControl,
    ProtocolViolation,
    Io,
    SocketBind,
    SocketTimeout,
    SocketRead,
    SocketWrite,
    Tls,
    TlsCertificate,
    TlsAuthentication,
    TlsHandshake,
    UnexpectedPeer,
    ConnectionId,
    TransportParameter,
    HandshakeConfirmation,
    PeerClosed {
        code: u64,
        frame_type: u64,
        reason: [u8; 64],
        reason_len: u8,
    },
}

pub fn initial_version_and_destination_id(
    input: &[u8],
) -> Result<(QuicVersion, Vector<u8>), QuicError> {
    if input.len() < 7 || input[0] & 0xc0 != 0xc0 {
        return Err(QuicError::InvalidPacket);
    }
    let version =
        QuicVersion::from_wire(u32::from_be_bytes([input[1], input[2], input[3], input[4]]))
            .ok_or(QuicError::InvalidPacket)?;
    if input[0] & 0xf0 != version.initial_type() {
        return Err(QuicError::InvalidPacket);
    }
    let length = input[5] as usize;
    if length > 20 || input.len() < 6 + length {
        return Err(QuicError::Truncated);
    }
    let mut id = Vector::new();
    id.try_extend_from_slice(&input[6..6 + length])
        .map_err(|_| QuicError::Allocation)?;
    Ok((version, id))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicRole {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketSpace {
    Initial,
    Handshake,
    Application,
}

const RECEIVE_PACKET_WINDOW: u64 = 4096;
const MAX_RECEIVE_RANGES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceivedPacket {
    New,
    Duplicate,
    TooOld,
}

/// Bounded authenticated packet-number history for one QUIC number space.
///
/// Callers must invoke `record` only after header protection and AEAD
/// authentication succeed. Ranges are inclusive, sorted, and coalesced; sparse
/// attacker-selected packet numbers therefore cannot create unbounded state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketReceiveState {
    largest: Option<u64>,
    ranges: Vector<(u64, u64)>,
}

impl PacketReceiveState {
    pub(crate) fn new() -> Self {
        Self {
            largest: None,
            ranges: Vector::new(),
        }
    }

    pub(crate) fn expected(&self) -> u64 {
        self.largest
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0)
    }

    pub(crate) fn record(&mut self, number: u64) -> Result<ReceivedPacket, QuicError> {
        if number >= (1 << 62) {
            return Err(QuicError::InvalidPacket);
        }
        if self
            .largest
            .is_some_and(|largest| number.saturating_add(RECEIVE_PACKET_WINDOW) < largest)
        {
            return Ok(ReceivedPacket::TooOld);
        }
        if self
            .ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&number))
        {
            return Ok(ReceivedPacket::Duplicate);
        }

        let mut insertion = 0;
        while insertion < self.ranges.len() && self.ranges[insertion].1 < number {
            insertion += 1;
        }
        self.ranges
            .try_insert(insertion, (number, number))
            .map_err(|_| QuicError::Allocation)?;
        if insertion > 0
            && self.ranges[insertion - 1].1.checked_add(1) == Some(self.ranges[insertion].0)
        {
            let end = self.ranges.remove(insertion).1;
            insertion -= 1;
            self.ranges[insertion].1 = end;
        }
        if insertion + 1 < self.ranges.len()
            && self.ranges[insertion].1.checked_add(1) == Some(self.ranges[insertion + 1].0)
        {
            let end = self.ranges.remove(insertion + 1).1;
            self.ranges[insertion].1 = end;
        }
        self.largest = Some(self.largest.map_or(number, |largest| largest.max(number)));
        let floor = self.largest.unwrap().saturating_sub(RECEIVE_PACKET_WINDOW);
        while self.ranges.first().is_some_and(|(_, end)| *end < floor) {
            self.ranges.remove(0);
        }
        while self.ranges.len() > MAX_RECEIVE_RANGES {
            self.ranges.remove(0);
        }
        Ok(ReceivedPacket::New)
    }

    pub(crate) fn ack_frame(&self) -> Option<QuicFrame> {
        let &(first_start, largest) = self.ranges.last()?;
        let mut encoded = Vector::new();
        let mut next_start = first_start;
        for &(start, end) in self.ranges[..self.ranges.len() - 1].iter().rev() {
            let gap = next_start.checked_sub(end)?.checked_sub(2)?;
            encoded.try_push((gap, end - start)).ok()?;
            next_start = start;
        }
        Some(QuicFrame::Ack {
            largest,
            delay: 0,
            first_range: largest - first_start,
            ranges: encoded,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicConnectionPhase {
    Handshaking,
    Active,
    Draining,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicConnectionState {
    role: QuicRole,
    phase: QuicConnectionPhase,
    address_validated: bool,
    bytes_received: u64,
    bytes_sent: u64,
    peer_max_data: u64,
    peer_max_stream_data: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    sent_stream_data: u64,
    opened_bidi: u64,
    next_bidi_stream: u64,
    opened_uni: u64,
    next_uni_stream: u64,
    pending_path_challenge: Option<[u8; 8]>,
}

impl QuicConnectionState {
    pub fn new(role: QuicRole, peer: &QuicTransportParameters) -> Self {
        Self {
            role,
            phase: QuicConnectionPhase::Handshaking,
            address_validated: role == QuicRole::Client,
            bytes_received: 0,
            bytes_sent: 0,
            peer_max_data: peer.initial_max_data,
            peer_max_stream_data: peer.initial_max_stream_data_bidi_remote,
            peer_max_streams_bidi: peer.initial_max_streams_bidi,
            peer_max_streams_uni: peer.initial_max_streams_uni,
            sent_stream_data: 0,
            opened_bidi: 0,
            next_bidi_stream: if role == QuicRole::Client { 0 } else { 1 },
            opened_uni: 0,
            next_uni_stream: if role == QuicRole::Client { 2 } else { 3 },
            pending_path_challenge: None,
        }
    }
    pub fn phase(&self) -> QuicConnectionPhase {
        self.phase
    }
    pub fn on_datagram_received(&mut self, bytes: usize) -> Result<(), QuicError> {
        self.bytes_received = self
            .bytes_received
            .checked_add(bytes as u64)
            .ok_or(QuicError::Limit)?;
        Ok(())
    }
    pub fn authorize_datagram_send(&mut self, bytes: usize) -> Result<(), QuicError> {
        let next = self
            .bytes_sent
            .checked_add(bytes as u64)
            .ok_or(QuicError::Limit)?;
        if self.role == QuicRole::Server
            && !self.address_validated
            && next > self.bytes_received.saturating_mul(3)
        {
            return Err(QuicError::FlowControl);
        }
        self.bytes_sent = next;
        Ok(())
    }
    pub fn validate_address(&mut self) {
        self.address_validated = true
    }
    pub fn activate(&mut self) -> Result<(), QuicError> {
        if self.phase != QuicConnectionPhase::Handshaking {
            return Err(QuicError::ProtocolViolation);
        }
        self.phase = QuicConnectionPhase::Active;
        Ok(())
    }
    pub fn open_bidi_stream(&mut self) -> Result<u64, QuicError> {
        if self.phase != QuicConnectionPhase::Active
            || self.opened_bidi >= self.peer_max_streams_bidi
        {
            return Err(QuicError::FlowControl);
        }
        let id = self.next_bidi_stream;
        self.next_bidi_stream = self
            .next_bidi_stream
            .checked_add(4)
            .ok_or(QuicError::Limit)?;
        self.opened_bidi += 1;
        Ok(id)
    }
    pub fn authorize_stream_send(&mut self, amount: usize) -> Result<(), QuicError> {
        let amount = amount as u64;
        let total = self
            .sent_stream_data
            .checked_add(amount)
            .ok_or(QuicError::Limit)?;
        if total > self.peer_max_data || amount > self.peer_max_stream_data {
            return Err(QuicError::FlowControl);
        }
        self.sent_stream_data = total;
        Ok(())
    }
    pub fn open_uni_stream(&mut self) -> Result<u64, QuicError> {
        if self.phase != QuicConnectionPhase::Active || self.opened_uni >= self.peer_max_streams_uni
        {
            return Err(QuicError::FlowControl);
        }
        let id = self.next_uni_stream;
        self.next_uni_stream = self
            .next_uni_stream
            .checked_add(4)
            .ok_or(QuicError::Limit)?;
        self.opened_uni += 1;
        Ok(id)
    }
    pub fn start_path_validation(&mut self, challenge: [u8; 8]) -> QuicFrame {
        self.pending_path_challenge = Some(challenge);
        QuicFrame::PathChallenge(challenge)
    }
    pub fn on_path_response(&mut self, response: [u8; 8]) -> Result<(), QuicError> {
        if self.pending_path_challenge != Some(response) {
            return Err(QuicError::ProtocolViolation);
        }
        self.pending_path_challenge = None;
        self.address_validated = true;
        Ok(())
    }
    pub fn close(&mut self) {
        self.phase = QuicConnectionPhase::Closed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportParameters {
    pub original_destination_connection_id: Option<Vector<u8>>,
    pub initial_source_connection_id: Vector<u8>,
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay_ms: u64,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
    pub chosen_version: Option<u32>,
    pub available_versions: Vector<u32>,
}

impl Default for QuicTransportParameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            initial_source_connection_id: Vector::new(),
            max_idle_timeout_ms: 30_000,
            max_udp_payload_size: 1200,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 256 << 10,
            initial_max_stream_data_bidi_remote: 256 << 10,
            initial_max_stream_data_uni: 256 << 10,
            initial_max_streams_bidi: 32,
            initial_max_streams_uni: 8,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            active_connection_id_limit: 2,
            disable_active_migration: false,
            chosen_version: None,
            available_versions: Vector::new(),
        }
    }
}
impl QuicTransportParameters {
    pub fn encode(&self) -> Result<Vector<u8>, QuicError> {
        if !(1200..=65527).contains(&self.max_udp_payload_size)
            || self.active_connection_id_limit < 2
            || self.ack_delay_exponent > 20
            || self.max_ack_delay_ms >= (1 << 14)
            || self.initial_source_connection_id.len() > 20
            || self
                .original_destination_connection_id
                .as_ref()
                .is_some_and(|id| id.len() > 20)
            || self.available_versions.len() > 64
            || self.available_versions.iter().any(|version| *version == 0)
            || self.chosen_version == Some(0)
        {
            return Err(QuicError::Limit);
        }
        let mut out = Vector::new();
        if let Some(id) = &self.original_destination_connection_id {
            put_varint(&mut out, 0)?;
            put_varint(&mut out, id.len() as u64)?;
            out.try_extend_from_slice(id)
                .map_err(|_| QuicError::Allocation)?;
        }
        for (id, value) in [
            (1, self.max_idle_timeout_ms),
            (3, self.max_udp_payload_size),
            (4, self.initial_max_data),
            (5, self.initial_max_stream_data_bidi_local),
            (6, self.initial_max_stream_data_bidi_remote),
            (7, self.initial_max_stream_data_uni),
            (8, self.initial_max_streams_bidi),
            (9, self.initial_max_streams_uni),
            (10, self.ack_delay_exponent),
            (11, self.max_ack_delay_ms),
            (14, self.active_connection_id_limit),
        ] {
            let mut encoded = Vector::new();
            put_varint(&mut encoded, value)?;
            put_varint(&mut out, id)?;
            put_varint(&mut out, encoded.len() as u64)?;
            out.try_extend_from_slice(&encoded)
                .map_err(|_| QuicError::Allocation)?;
        }
        if self.disable_active_migration {
            put_varint(&mut out, 12)?;
            put_varint(&mut out, 0)?
        }
        if let Some(chosen) = self.chosen_version {
            if self.available_versions.is_empty() {
                return Err(QuicError::TransportParameter);
            }
            let mut versions = Vector::new();
            versions
                .try_extend_from_slice(&chosen.to_be_bytes())
                .map_err(|_| QuicError::Allocation)?;
            for version in &self.available_versions {
                versions
                    .try_extend_from_slice(&version.to_be_bytes())
                    .map_err(|_| QuicError::Allocation)?;
            }
            put_varint(&mut out, 0x11)?;
            put_varint(&mut out, versions.len() as u64)?;
            out.try_extend_from_slice(&versions)
                .map_err(|_| QuicError::Allocation)?;
        }
        put_varint(&mut out, 15)?;
        put_varint(&mut out, self.initial_source_connection_id.len() as u64)?;
        out.try_extend_from_slice(&self.initial_source_connection_id)
            .map_err(|_| QuicError::Allocation)?;
        Ok(out)
    }
    pub fn decode(input: &[u8]) -> Result<Self, QuicError> {
        let mut result = Self::default();
        let mut at = 0;
        let mut seen = 0u32;
        while at < input.len() {
            let id = take_varint(input, &mut at)?;
            let n = usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
            let end = at.checked_add(n).ok_or(QuicError::Limit)?;
            if end > input.len() {
                return Err(QuicError::Truncated);
            }
            let bit = match id {
                0 => Some(10),
                1 => Some(0),
                3 => Some(1),
                4 => Some(2),
                5 => Some(3),
                6 => Some(4),
                8 => Some(5),
                7 => Some(6),
                9 => Some(7),
                12 => Some(8),
                14 => Some(9),
                10 => Some(11),
                11 => Some(12),
                15 => Some(13),
                0x11 => Some(14),
                _ => None,
            };
            if let Some(bit) = bit {
                if seen & (1 << bit) != 0 {
                    return Err(QuicError::InvalidPacket);
                }
                seen |= 1 << bit;
            }
            let mut field_at = at;
            if matches!(id, 0 | 15) {
                if n > 20 {
                    return Err(QuicError::Limit);
                }
                let mut connection_id = Vector::new();
                connection_id
                    .try_extend_from_slice(&input[at..end])
                    .map_err(|_| QuicError::Allocation)?;
                if id == 0 {
                    result.original_destination_connection_id = Some(connection_id);
                } else {
                    result.initial_source_connection_id = connection_id;
                }
                at = end;
                continue;
            }
            if id == 0x11 {
                if n < 8 || n % 4 != 0 {
                    return Err(QuicError::TransportParameter);
                }
                let chosen = u32::from_be_bytes(
                    input[at..at + 4]
                        .try_into()
                        .map_err(|_| QuicError::Truncated)?,
                );
                if chosen == 0 {
                    return Err(QuicError::TransportParameter);
                }
                result.chosen_version = Some(chosen);
                at += 4;
                while at < end {
                    let version = u32::from_be_bytes(
                        input[at..at + 4]
                            .try_into()
                            .map_err(|_| QuicError::Truncated)?,
                    );
                    if version == 0 || result.available_versions.contains(&version) {
                        return Err(QuicError::TransportParameter);
                    }
                    result
                        .available_versions
                        .try_push(version)
                        .map_err(|_| QuicError::Allocation)?;
                    at += 4;
                }
                continue;
            }
            if bit.is_none() {
                at = end;
                continue;
            }
            let value = if id == 12 {
                if n != 0 {
                    return Err(QuicError::InvalidPacket);
                }
                0
            } else {
                let value = take_varint(&input[..end], &mut field_at)?;
                if field_at != end {
                    return Err(QuicError::InvalidPacket);
                }
                value
            };
            match id {
                1 => result.max_idle_timeout_ms = value,
                3 => result.max_udp_payload_size = value,
                4 => result.initial_max_data = value,
                5 => result.initial_max_stream_data_bidi_local = value,
                6 => result.initial_max_stream_data_bidi_remote = value,
                7 => result.initial_max_stream_data_uni = value,
                8 => result.initial_max_streams_bidi = value,
                9 => result.initial_max_streams_uni = value,
                10 => result.ack_delay_exponent = value,
                11 => result.max_ack_delay_ms = value,
                12 => result.disable_active_migration = true,
                14 => result.active_connection_id_limit = value,
                _ => {}
            }
            at = end;
        }
        if !(1200..=65527).contains(&result.max_udp_payload_size)
            || result.active_connection_id_limit < 2
            || result.ack_delay_exponent > 20
            || result.max_ack_delay_ms >= (1 << 14)
        {
            return Err(QuicError::Limit);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentPacket {
    pub number: u64,
    pub sent_micros: u64,
    pub bytes: u64,
    pub ack_eliciting: bool,
    pub in_flight: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicRecovery {
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub slow_start_threshold: u64,
    pub smoothed_rtt_micros: u64,
    pub rtt_variance_micros: u64,
    pub minimum_rtt_micros: u64,
    pub latest_rtt_micros: u64,
    max_datagram: u64,
    recovery_start_micros: u64,
}
impl QuicRecovery {
    pub fn new(max_datagram: u64) -> Result<Self, QuicError> {
        if !(1200..=65527).contains(&max_datagram) {
            return Err(QuicError::Limit);
        }
        let window = (10 * max_datagram).min((2 * max_datagram).max(14720));
        Ok(Self {
            congestion_window: window,
            bytes_in_flight: 0,
            slow_start_threshold: u64::MAX,
            smoothed_rtt_micros: 0,
            rtt_variance_micros: 0,
            minimum_rtt_micros: u64::MAX,
            latest_rtt_micros: 0,
            max_datagram,
            recovery_start_micros: 0,
        })
    }
    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight
            .checked_add(bytes)
            .is_some_and(|v| v <= self.congestion_window)
    }
    pub fn on_sent(&mut self, packet: SentPacket) -> Result<(), QuicError> {
        if packet.in_flight {
            self.bytes_in_flight = self
                .bytes_in_flight
                .checked_add(packet.bytes)
                .ok_or(QuicError::Limit)?
        }
        Ok(())
    }
    pub fn on_ack(
        &mut self,
        packet: SentPacket,
        ack_time_micros: u64,
        ack_delay_micros: u64,
    ) -> Result<(), QuicError> {
        if ack_time_micros < packet.sent_micros {
            return Err(QuicError::InvalidPacket);
        }
        let sample = ack_time_micros - packet.sent_micros;
        self.latest_rtt_micros = sample;
        self.minimum_rtt_micros = self.minimum_rtt_micros.min(sample);
        let adjusted = if sample > self.minimum_rtt_micros.saturating_add(ack_delay_micros) {
            sample - ack_delay_micros
        } else {
            sample
        };
        if self.smoothed_rtt_micros == 0 {
            self.smoothed_rtt_micros = adjusted;
            self.rtt_variance_micros = adjusted / 2
        } else {
            let difference = self.smoothed_rtt_micros.abs_diff(adjusted);
            self.rtt_variance_micros = (3 * self.rtt_variance_micros + difference) / 4;
            self.smoothed_rtt_micros = (7 * self.smoothed_rtt_micros + adjusted) / 8
        }
        if packet.in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.bytes)
        }
        if packet.ack_eliciting && packet.sent_micros > self.recovery_start_micros {
            if self.congestion_window < self.slow_start_threshold {
                self.congestion_window = self.congestion_window.saturating_add(packet.bytes)
            } else {
                let increase =
                    self.max_datagram.saturating_mul(packet.bytes) / self.congestion_window.max(1);
                self.congestion_window = self.congestion_window.saturating_add(increase)
            }
        }
        Ok(())
    }
    pub fn on_loss(&mut self, packet: SentPacket, now_micros: u64) {
        if packet.in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.bytes)
        }
        if packet.sent_micros <= self.recovery_start_micros {
            return;
        }
        self.recovery_start_micros = now_micros;
        self.congestion_window = (self.congestion_window / 2).max(2 * self.max_datagram);
        self.slow_start_threshold = self.congestion_window;
    }
    pub fn loss_delay_micros(&self) -> u64 {
        let base = self.latest_rtt_micros.max(self.smoothed_rtt_micros);
        (base.saturating_mul(9) / 8).max(1_000)
    }
    pub fn probe_timeout_micros(
        &self,
        max_ack_delay_micros: u64,
        handshake_confirmed: bool,
    ) -> u64 {
        let base = self.smoothed_rtt_micros.max(333_000);
        let variance = (4 * self.rtt_variance_micros).max(1_000);
        base.saturating_add(variance)
            .saturating_add(if handshake_confirmed {
                max_ack_delay_micros
            } else {
                0
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicFrame {
    Padding,
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
        ranges: Vector<(u64, u64)>,
    },
    Crypto {
        offset: u64,
        data: Vector<u8>,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: Vector<u8>,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        maximum: u64,
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: Vector<u8>,
        reset_token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        code: u64,
        frame_type: u64,
        reason: Vector<u8>,
    },
    HandshakeDone,
}

fn put_varint(out: &mut Vector<u8>, value: u64) -> Result<(), QuicError> {
    if value < (1 << 6) {
        out.try_push(value as u8).map_err(|_| QuicError::Allocation)
    } else if value < (1 << 14) {
        out.try_extend_from_slice(&((value as u16) | 0x4000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else if value < (1 << 30) {
        out.try_extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else if value < (1 << 62) {
        out.try_extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else {
        Err(QuicError::InvalidInteger)
    }
}

fn take_varint(input: &[u8], at: &mut usize) -> Result<u64, QuicError> {
    let first = *input.get(*at).ok_or(QuicError::Truncated)?;
    let length = 1usize << (first >> 6);
    let end = at.checked_add(length).ok_or(QuicError::Limit)?;
    if end > input.len() {
        return Err(QuicError::Truncated);
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &input[*at + 1..end] {
        value = (value << 8) | *byte as u64;
    }
    *at = end;
    Ok(value)
}

impl QuicFrame {
    pub fn encode(&self, out: &mut Vector<u8>) -> Result<(), QuicError> {
        match self {
            Self::Padding => out.try_push(0).map_err(|_| QuicError::Allocation),
            Self::Ping => out.try_push(1).map_err(|_| QuicError::Allocation),
            Self::Ack {
                largest,
                delay,
                first_range,
                ranges,
            } => {
                put_varint(out, 2)?;
                put_varint(out, *largest)?;
                put_varint(out, *delay)?;
                put_varint(out, ranges.len() as u64)?;
                put_varint(out, *first_range)?;
                for (gap, range) in ranges {
                    put_varint(out, *gap)?;
                    put_varint(out, *range)?;
                }
                Ok(())
            }
            Self::Crypto { offset, data } => {
                put_varint(out, 6)?;
                put_varint(out, *offset)?;
                put_varint(out, data.len() as u64)?;
                out.try_extend_from_slice(data)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                put_varint(out, 0x0a | u64::from(*offset != 0) * 4 | u64::from(*fin))?;
                put_varint(out, *id)?;
                if *offset != 0 {
                    put_varint(out, *offset)?;
                }
                put_varint(out, data.len() as u64)?;
                out.try_extend_from_slice(data)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::MaxData(value) => {
                put_varint(out, 0x10)?;
                put_varint(out, *value)
            }
            Self::MaxStreamData { id, maximum } => {
                put_varint(out, 0x11)?;
                put_varint(out, *id)?;
                put_varint(out, *maximum)
            }
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                reset_token,
            } => {
                if connection_id.is_empty()
                    || connection_id.len() > 20
                    || retire_prior_to > sequence
                {
                    return Err(QuicError::InvalidFrame);
                }
                put_varint(out, 0x18)?;
                put_varint(out, *sequence)?;
                put_varint(out, *retire_prior_to)?;
                out.try_push(connection_id.len() as u8)
                    .map_err(|_| QuicError::Allocation)?;
                out.try_extend_from_slice(connection_id)
                    .map_err(|_| QuicError::Allocation)?;
                out.try_extend_from_slice(reset_token)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::RetireConnectionId(sequence) => {
                put_varint(out, 0x19)?;
                put_varint(out, *sequence)
            }
            Self::PathChallenge(value) => {
                put_varint(out, 0x1a)?;
                out.try_extend_from_slice(value)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::PathResponse(value) => {
                put_varint(out, 0x1b)?;
                out.try_extend_from_slice(value)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::ConnectionClose {
                code,
                frame_type,
                reason,
            } => {
                put_varint(out, 0x1c)?;
                put_varint(out, *code)?;
                put_varint(out, *frame_type)?;
                put_varint(out, reason.len() as u64)?;
                out.try_extend_from_slice(reason)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::HandshakeDone => put_varint(out, 0x1e),
        }
    }

    pub fn decode(input: &[u8], at: &mut usize) -> Result<Self, QuicError> {
        let kind = take_varint(input, at)?;
        let bytes =
            |input: &[u8], at: &mut usize, length: usize| -> Result<Vector<u8>, QuicError> {
                let end = at.checked_add(length).ok_or(QuicError::Limit)?;
                if end > input.len() {
                    return Err(QuicError::Truncated);
                }
                let mut out = Vector::new();
                out.try_extend_from_slice(&input[*at..end])
                    .map_err(|_| QuicError::Allocation)?;
                *at = end;
                Ok(out)
            };
        match kind {
            0 => Ok(Self::Padding),
            1 => Ok(Self::Ping),
            2 => {
                let largest = take_varint(input, at)?;
                let delay = take_varint(input, at)?;
                let range_count = take_varint(input, at)?;
                if range_count > 256 {
                    return Err(QuicError::InvalidFrame);
                }
                let first_range = take_varint(input, at)?;
                if first_range > largest {
                    return Err(QuicError::InvalidFrame);
                }
                let mut ranges = Vector::new();
                let mut smallest = largest - first_range;
                for _ in 0..range_count {
                    let gap = take_varint(input, at)?;
                    let range = take_varint(input, at)?;
                    smallest = smallest
                        .checked_sub(gap.checked_add(2).ok_or(QuicError::Limit)?)
                        .and_then(|value| value.checked_sub(range))
                        .ok_or(QuicError::InvalidFrame)?;
                    ranges
                        .try_push((gap, range))
                        .map_err(|_| QuicError::Allocation)?;
                }
                Ok(Self::Ack {
                    largest,
                    delay,
                    first_range,
                    ranges,
                })
            }
            6 => {
                let offset = take_varint(input, at)?;
                let n = usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?;
                Ok(Self::Crypto {
                    offset,
                    data: bytes(input, at, n)?,
                })
            }
            0x08..=0x0f => {
                let id = take_varint(input, at)?;
                let offset = if kind & 4 != 0 {
                    take_varint(input, at)?
                } else {
                    0
                };
                let n = if kind & 2 != 0 {
                    usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?
                } else {
                    input.len() - *at
                };
                Ok(Self::Stream {
                    id,
                    offset,
                    fin: kind & 1 != 0,
                    data: bytes(input, at, n)?,
                })
            }
            0x10 => Ok(Self::MaxData(take_varint(input, at)?)),
            0x11 => Ok(Self::MaxStreamData {
                id: take_varint(input, at)?,
                maximum: take_varint(input, at)?,
            }),
            0x18 => {
                let sequence = take_varint(input, at)?;
                let retire_prior_to = take_varint(input, at)?;
                let length = *input.get(*at).ok_or(QuicError::Truncated)? as usize;
                *at += 1;
                if length == 0 || length > 20 || retire_prior_to > sequence {
                    return Err(QuicError::InvalidFrame);
                }
                let connection_id = bytes(input, at, length)?;
                let token = bytes(input, at, 16)?;
                let mut reset_token = [0; 16];
                reset_token.copy_from_slice(&token);
                Ok(Self::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    reset_token,
                })
            }
            0x19 => Ok(Self::RetireConnectionId(take_varint(input, at)?)),
            0x1a | 0x1b => {
                let value = bytes(input, at, 8)?;
                let mut a = [0; 8];
                a.copy_from_slice(&value);
                Ok(if kind == 0x1a {
                    Self::PathChallenge(a)
                } else {
                    Self::PathResponse(a)
                })
            }
            0x1c => {
                let code = take_varint(input, at)?;
                let frame_type = take_varint(input, at)?;
                let n = usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?;
                Ok(Self::ConnectionClose {
                    code,
                    frame_type,
                    reason: bytes(input, at, n)?,
                })
            }
            0x1e => Ok(Self::HandshakeDone),
            _ => Err(QuicError::InvalidFrame),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub header: [u8; 16],
}
impl QuicInitialKeys {
    pub fn derive(destination_id: &[u8], role: QuicRole) -> Result<Self, QuicError> {
        Self::derive_for(QuicVersion::V1, destination_id, role)
    }

    pub fn derive_for(
        version: QuicVersion,
        destination_id: &[u8],
        role: QuicRole,
    ) -> Result<Self, QuicError> {
        if destination_id.len() > 20 {
            return Err(QuicError::Limit);
        }
        let initial = hkdf_extract(version.initial_salt(), destination_id);
        let mut secret = [0; 32];
        let label = if role == QuicRole::Client {
            b"client in".as_slice()
        } else {
            b"server in".as_slice()
        };
        if !hkdf_expand_label(&initial, label, &[], &mut secret) {
            return Err(QuicError::Crypto);
        }
        let mut key = [0; 16];
        let mut iv = [0; 12];
        let mut header = [0; 16];
        if !hkdf_expand_label(&secret, version.key_label(), &[], &mut key)
            || !hkdf_expand_label(&secret, version.iv_label(), &[], &mut iv)
            || !hkdf_expand_label(&secret, version.hp_label(), &[], &mut header)
        {
            return Err(QuicError::Crypto);
        }
        Ok(Self { key, iv, header })
    }
    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in packet.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= *b
        }
        n
    }

    pub fn from_traffic_secret(secret: &[u8; 32]) -> Result<Self, QuicError> {
        Self::from_traffic_secret_for(QuicVersion::V1, secret)
    }

    pub fn from_traffic_secret_for(
        version: QuicVersion,
        secret: &[u8; 32],
    ) -> Result<Self, QuicError> {
        let mut key = [0; 16];
        let mut iv = [0; 12];
        let mut header = [0; 16];
        if !hkdf_expand_label(secret, version.key_label(), &[], &mut key)
            || !hkdf_expand_label(secret, version.iv_label(), &[], &mut iv)
            || !hkdf_expand_label(secret, version.hp_label(), &[], &mut header)
        {
            return Err(QuicError::Crypto);
        }
        Ok(Self { key, iv, header })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortPacket {
    pub destination_id: Vector<u8>,
    pub packet_number: u64,
    pub key_phase: bool,
    pub payload: Vector<u8>,
}

impl ShortPacket {
    pub fn seal(&self, keys: &QuicInitialKeys) -> Result<Vector<u8>, QuicError> {
        if self.destination_id.len() > 20 || self.payload.len() > MAX_DATAGRAM {
            return Err(QuicError::Limit);
        }
        let packet_number_length = 4usize;
        let mut out = Vector::new();
        out.try_push(0x40 | (u8::from(self.key_phase) << 2) | 3)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.destination_id)
            .map_err(|_| QuicError::Allocation)?;
        let packet_number_offset = out.len();
        out.try_extend_from_slice(&(self.packet_number as u32).to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        let mut encrypted = Vector::new();
        encrypted
            .try_resize(self.payload.len(), 0)
            .map_err(|_| QuicError::Allocation)?;
        let mut tag = [0; 16];
        if !aes128_gcm_seal(
            &keys.key,
            &keys.nonce(self.packet_number),
            &out,
            &self.payload,
            &mut encrypted,
            &mut tag,
        ) {
            return Err(QuicError::Crypto);
        }
        out.try_extend_from_slice(&encrypted)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&tag)
            .map_err(|_| QuicError::Allocation)?;
        if out.len() < packet_number_offset + 4 + 16 {
            return Err(QuicError::InvalidPacket);
        }
        let mut sample = [0; 16];
        sample.copy_from_slice(&out[packet_number_offset + 4..packet_number_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        out[0] ^= mask[0] & 0x1f;
        for index in 0..packet_number_length {
            out[packet_number_offset + index] ^= mask[index + 1];
        }
        Ok(out)
    }

    pub fn open(
        input: &[u8],
        destination_id_length: usize,
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<Self, QuicError> {
        if destination_id_length > 20
            || input.len() < 1 + destination_id_length + 4 + 16
            || input[0] & 0x80 != 0
        {
            return Err(QuicError::InvalidPacket);
        }
        let packet_number_offset = 1 + destination_id_length;
        let mut sample = [0; 16];
        sample.copy_from_slice(
            input
                .get(packet_number_offset + 4..packet_number_offset + 20)
                .ok_or(QuicError::Truncated)?,
        );
        let mask = aes128_encrypt_block(&keys.header, &sample);
        let first = input[0] ^ (mask[0] & 0x1f);
        if first & 0x40 == 0 || first & 0x18 != 0 {
            return Err(QuicError::InvalidPacket);
        }
        let packet_number_length = (first as usize & 3) + 1;
        let mut truncated = 0u64;
        let mut packet_number_bytes = [0; 4];
        for index in 0..packet_number_length {
            let byte = input[packet_number_offset + index] ^ mask[index + 1];
            packet_number_bytes[4 - packet_number_length + index] = byte;
            truncated = (truncated << 8) | byte as u64;
        }
        let packet_number =
            reconstruct_packet_number(truncated, packet_number_length, expected_packet_number)?;
        let aad_end = packet_number_offset + packet_number_length;
        if input.len() < aad_end + 16 {
            return Err(QuicError::Truncated);
        }
        let mut aad = Vector::new();
        aad.try_extend_from_slice(&input[..aad_end])
            .map_err(|_| QuicError::Allocation)?;
        aad[0] = first;
        aad[packet_number_offset..aad_end]
            .copy_from_slice(&packet_number_bytes[4 - packet_number_length..]);
        let encrypted_end = input.len() - 16;
        let mut tag = [0; 16];
        tag.copy_from_slice(&input[encrypted_end..]);
        let mut payload = Vector::new();
        payload
            .try_resize(encrypted_end - aad_end, 0)
            .map_err(|_| QuicError::Allocation)?;
        if !aes128_gcm_open(
            &keys.key,
            &keys.nonce(packet_number),
            &aad,
            &input[aad_end..encrypted_end],
            &tag,
            &mut payload,
        ) {
            return Err(QuicError::Crypto);
        }
        let mut destination_id = Vector::new();
        destination_id
            .try_extend_from_slice(&input[1..packet_number_offset])
            .map_err(|_| QuicError::Allocation)?;
        Ok(Self {
            destination_id,
            packet_number,
            key_phase: first & 4 != 0,
            payload,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicStreamAssembler {
    bytes: Vector<u8>,
    chunks: Vector<StreamChunk>,
    final_size: Option<usize>,
    limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamChunk {
    offset: usize,
    bytes: Vector<u8>,
}

const MAX_STREAM_CHUNKS: usize = 256;
const MAX_STREAM_GAP: usize = 1024 * 1024;
impl QuicStreamAssembler {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vector::new(),
            chunks: Vector::new(),
            final_size: None,
            limit,
        }
    }
    pub fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), QuicError> {
        let offset = usize::try_from(offset).map_err(|_| QuicError::Limit)?;
        let end = offset.checked_add(data.len()).ok_or(QuicError::Limit)?;
        if end > self.limit
            || offset.saturating_sub(self.bytes.len()) > MAX_STREAM_GAP
            || self.final_size.is_some_and(|size| end > size)
        {
            return Err(QuicError::Limit);
        }
        if fin {
            if self.final_size.is_some_and(|size| size != end) {
                return Err(QuicError::InvalidFrame);
            }
            self.final_size = Some(end)
        }
        let prefix_overlap = end.min(self.bytes.len()).saturating_sub(offset);
        if prefix_overlap != 0
            && self.bytes[offset..offset + prefix_overlap] != data[..prefix_overlap]
        {
            return Err(QuicError::InvalidFrame);
        }
        for chunk in &self.chunks {
            let chunk_end = chunk.offset + chunk.bytes.len();
            let overlap_start = offset.max(chunk.offset);
            let overlap_end = end.min(chunk_end);
            if overlap_start < overlap_end
                && data[overlap_start - offset..overlap_end - offset]
                    != chunk.bytes[overlap_start - chunk.offset..overlap_end - chunk.offset]
            {
                return Err(QuicError::InvalidFrame);
            }
        }

        let mut cursor = offset.max(self.bytes.len());
        while cursor < end {
            if let Some(chunk) = self
                .chunks
                .iter()
                .find(|chunk| chunk.offset <= cursor && cursor < chunk.offset + chunk.bytes.len())
            {
                cursor = (chunk.offset + chunk.bytes.len()).min(end);
                continue;
            }
            let next = self
                .chunks
                .iter()
                .filter(|chunk| chunk.offset > cursor)
                .map(|chunk| chunk.offset)
                .min()
                .unwrap_or(end)
                .min(end);
            let mut owned = Vector::new();
            owned
                .try_extend_from_slice(&data[cursor - offset..next - offset])
                .map_err(|_| QuicError::Allocation)?;
            let insertion = self
                .chunks
                .iter()
                .position(|chunk| chunk.offset > cursor)
                .unwrap_or(self.chunks.len());
            self.chunks
                .try_insert(
                    insertion,
                    StreamChunk {
                        offset: cursor,
                        bytes: owned,
                    },
                )
                .map_err(|_| QuicError::Allocation)?;
            if self.chunks.len() > MAX_STREAM_CHUNKS {
                return Err(QuicError::Limit);
            }
            cursor = next;
        }
        while self
            .chunks
            .first()
            .is_some_and(|chunk| chunk.offset <= self.bytes.len())
        {
            let chunk = self.chunks.remove(0);
            let already = self.bytes.len().saturating_sub(chunk.offset);
            if already < chunk.bytes.len() {
                self.bytes
                    .try_extend_from_slice(&chunk.bytes[already..])
                    .map_err(|_| QuicError::Allocation)?;
            }
        }
        Ok(())
    }
    pub fn contiguous(&self) -> &[u8] {
        &self.bytes
    }
    pub fn is_finished(&self) -> bool {
        self.final_size == Some(self.bytes.len())
    }
    pub fn consume(&mut self, amount: usize) -> Result<(), QuicError> {
        if amount > self.bytes.len() {
            return Err(QuicError::InvalidFrame);
        }
        let remaining = self.bytes.len() - amount;
        self.bytes.copy_within(amount.., 0);
        self.bytes.truncate(remaining);
        for chunk in &mut self.chunks {
            chunk.offset = chunk
                .offset
                .checked_sub(amount)
                .ok_or(QuicError::InvalidFrame)?;
        }
        if let Some(size) = &mut self.final_size {
            *size -= amount
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialPacket {
    pub destination_id: Vector<u8>,
    pub source_id: Vector<u8>,
    pub packet_number: u64,
    pub payload: Vector<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakePacket {
    pub destination_id: Vector<u8>,
    pub source_id: Vector<u8>,
    pub packet_number: u64,
    pub payload: Vector<u8>,
}

impl HandshakePacket {
    pub fn seal(&self, keys: &QuicInitialKeys) -> Result<Vector<u8>, QuicError> {
        self.seal_for(QuicVersion::V1, keys)
    }

    pub fn seal_for(
        &self,
        version: QuicVersion,
        keys: &QuicInitialKeys,
    ) -> Result<Vector<u8>, QuicError> {
        if self.destination_id.len() > 20
            || self.source_id.len() > 20
            || self.payload.len() > MAX_DATAGRAM
        {
            return Err(QuicError::Limit);
        }
        let packet_number_length = 4usize;
        let mut out = Vector::new();
        out.try_push(version.handshake_type() | (packet_number_length as u8 - 1))
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&version.wire().to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.destination_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.destination_id)
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.source_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.source_id)
            .map_err(|_| QuicError::Allocation)?;
        put_varint(
            &mut out,
            (packet_number_length + self.payload.len() + 16) as u64,
        )?;
        let packet_number_offset = out.len();
        out.try_extend_from_slice(&(self.packet_number as u32).to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        let mut encrypted = Vector::new();
        encrypted
            .try_resize(self.payload.len(), 0)
            .map_err(|_| QuicError::Allocation)?;
        let mut tag = [0; 16];
        if !aes128_gcm_seal(
            &keys.key,
            &keys.nonce(self.packet_number),
            &out,
            &self.payload,
            &mut encrypted,
            &mut tag,
        ) {
            return Err(QuicError::Crypto);
        }
        out.try_extend_from_slice(&encrypted)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&tag)
            .map_err(|_| QuicError::Allocation)?;
        if out.len() < packet_number_offset + 20 {
            return Err(QuicError::InvalidPacket);
        }
        let mut sample = [0; 16];
        sample.copy_from_slice(&out[packet_number_offset + 4..packet_number_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        out[0] ^= mask[0] & 0x0f;
        for index in 0..packet_number_length {
            out[packet_number_offset + index] ^= mask[index + 1];
        }
        Ok(out)
    }

    pub fn open(
        input: &[u8],
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<(Self, usize), QuicError> {
        Self::open_for(QuicVersion::V1, input, keys, expected_packet_number)
    }

    pub fn open_for(
        version: QuicVersion,
        input: &[u8],
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<(Self, usize), QuicError> {
        if input.len() < 7 || input[0] & 0xf0 != version.handshake_type() || input[0] & 0x40 == 0 {
            return Err(QuicError::InvalidPacket);
        }
        if u32::from_be_bytes([input[1], input[2], input[3], input[4]]) != version.wire() {
            return Err(QuicError::InvalidPacket);
        }
        let mut at = 5;
        let destination_length = *input.get(at).ok_or(QuicError::Truncated)? as usize;
        at += 1;
        if destination_length > 20 || input.len().saturating_sub(at) < destination_length + 1 {
            return Err(QuicError::InvalidPacket);
        }
        let mut destination_id = Vector::new();
        destination_id
            .try_extend_from_slice(&input[at..at + destination_length])
            .map_err(|_| QuicError::Allocation)?;
        at += destination_length;
        let source_length = input[at] as usize;
        at += 1;
        if source_length > 20 || input.len().saturating_sub(at) < source_length {
            return Err(QuicError::InvalidPacket);
        }
        let mut source_id = Vector::new();
        source_id
            .try_extend_from_slice(&input[at..at + source_length])
            .map_err(|_| QuicError::Allocation)?;
        at += source_length;
        let protected_length =
            usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
        let packet_end = at.checked_add(protected_length).ok_or(QuicError::Limit)?;
        if packet_end > input.len() || protected_length < 17 || at + 20 > packet_end {
            return Err(QuicError::Truncated);
        }
        let packet_number_offset = at;
        let mut sample = [0; 16];
        sample.copy_from_slice(&input[packet_number_offset + 4..packet_number_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        let first = input[0] ^ (mask[0] & 0x0f);
        if first & 0x30 != version.handshake_type() & 0x30 || first & 0x0c != 0 {
            return Err(QuicError::InvalidPacket);
        }
        let packet_number_length = (first as usize & 3) + 1;
        if protected_length < packet_number_length + 16 {
            return Err(QuicError::Truncated);
        }
        let mut truncated = 0u64;
        let mut number = [0; 4];
        for index in 0..packet_number_length {
            let byte = input[packet_number_offset + index] ^ mask[index + 1];
            number[4 - packet_number_length + index] = byte;
            truncated = (truncated << 8) | byte as u64;
        }
        let packet_number =
            reconstruct_packet_number(truncated, packet_number_length, expected_packet_number)?;
        let aad_end = packet_number_offset + packet_number_length;
        let mut aad = Vector::new();
        aad.try_extend_from_slice(&input[..aad_end])
            .map_err(|_| QuicError::Allocation)?;
        aad[0] = first;
        aad[packet_number_offset..aad_end].copy_from_slice(&number[4 - packet_number_length..]);
        let encrypted_end = packet_end - 16;
        let mut tag = [0; 16];
        tag.copy_from_slice(&input[encrypted_end..packet_end]);
        let mut payload = Vector::new();
        payload
            .try_resize(encrypted_end - aad_end, 0)
            .map_err(|_| QuicError::Allocation)?;
        if !aes128_gcm_open(
            &keys.key,
            &keys.nonce(packet_number),
            &aad,
            &input[aad_end..encrypted_end],
            &tag,
            &mut payload,
        ) {
            return Err(QuicError::Crypto);
        }
        Ok((
            Self {
                destination_id,
                source_id,
                packet_number,
                payload,
            },
            packet_end,
        ))
    }
}

impl InitialPacket {
    pub fn seal_padded(&self, keys: &QuicInitialKeys) -> Result<Vector<u8>, QuicError> {
        self.seal_padded_for(QuicVersion::V1, keys)
    }

    pub fn seal_padded_for(
        &self,
        version: QuicVersion,
        keys: &QuicInitialKeys,
    ) -> Result<Vector<u8>, QuicError> {
        let mut packet = self.clone();
        loop {
            let sealed = packet.seal_for(version, keys)?;
            if sealed.len() >= 1200 {
                return Ok(sealed);
            }
            packet
                .payload
                .try_resize(packet.payload.len() + (1200 - sealed.len()), 0)
                .map_err(|_| QuicError::Allocation)?;
        }
    }
    pub fn seal(&self, keys: &QuicInitialKeys) -> Result<Vector<u8>, QuicError> {
        self.seal_for(QuicVersion::V1, keys)
    }

    pub fn seal_for(
        &self,
        version: QuicVersion,
        keys: &QuicInitialKeys,
    ) -> Result<Vector<u8>, QuicError> {
        if self.destination_id.len() > 20
            || self.source_id.len() > 20
            || self.payload.len() > MAX_DATAGRAM
        {
            return Err(QuicError::Limit);
        }
        let pn_len = 4usize;
        let mut out = Vector::new();
        out.try_push(version.initial_type() | (pn_len as u8 - 1))
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&version.wire().to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.destination_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.destination_id)
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.source_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.source_id)
            .map_err(|_| QuicError::Allocation)?;
        put_varint(&mut out, 0)?;
        put_varint(&mut out, (pn_len + self.payload.len() + 16) as u64)?;
        let pn_offset = out.len();
        out.try_extend_from_slice(&(self.packet_number as u32).to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        let aad_len = out.len();
        let mut encrypted = Vector::new();
        encrypted
            .try_reserve(self.payload.len())
            .map_err(|_| QuicError::Allocation)?;
        for _ in 0..self.payload.len() {
            encrypted.push(0)
        }
        let mut tag = [0; 16];
        if !aes128_gcm_seal(
            &keys.key,
            &keys.nonce(self.packet_number),
            &out[..aad_len],
            &self.payload,
            &mut encrypted,
            &mut tag,
        ) {
            return Err(QuicError::Crypto);
        }
        out.try_extend_from_slice(&encrypted)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&tag)
            .map_err(|_| QuicError::Allocation)?;
        if out.len() < pn_offset + 4 + 16 {
            return Err(QuicError::InvalidPacket);
        }
        let mut sample = [0; 16];
        sample.copy_from_slice(&out[pn_offset + 4..pn_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        out[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            out[pn_offset + i] ^= mask[i + 1]
        }
        Ok(out)
    }

    pub fn open(
        input: &[u8],
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<(Self, usize), QuicError> {
        Self::open_for(QuicVersion::V1, input, keys, expected_packet_number)
    }

    pub fn open_for(
        version: QuicVersion,
        input: &[u8],
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<(Self, usize), QuicError> {
        if input.len() < 7 || input[0] & 0xf0 != version.initial_type() {
            return Err(QuicError::InvalidPacket);
        }
        if u32::from_be_bytes([input[1], input[2], input[3], input[4]]) != version.wire() {
            return Err(QuicError::InvalidPacket);
        }
        let mut at = 5;
        let destination_length = *input.get(at).ok_or(QuicError::Truncated)? as usize;
        at += 1;
        if destination_length > 20 || input.len().saturating_sub(at) < destination_length + 1 {
            return Err(QuicError::InvalidPacket);
        }
        let mut destination_id = Vector::new();
        destination_id
            .try_extend_from_slice(&input[at..at + destination_length])
            .map_err(|_| QuicError::Allocation)?;
        at += destination_length;
        let source_length = input[at] as usize;
        at += 1;
        if source_length > 20 || input.len().saturating_sub(at) < source_length {
            return Err(QuicError::InvalidPacket);
        }
        let mut source_id = Vector::new();
        source_id
            .try_extend_from_slice(&input[at..at + source_length])
            .map_err(|_| QuicError::Allocation)?;
        at += source_length;
        let token_length =
            usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
        if token_length != 0 || input.len().saturating_sub(at) < token_length {
            return Err(QuicError::InvalidPacket);
        }
        at += token_length;
        let protected_length =
            usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
        let packet_end = at.checked_add(protected_length).ok_or(QuicError::Limit)?;
        if packet_end > input.len() || protected_length < 1 + 16 || at + 4 + 16 > packet_end {
            return Err(QuicError::Truncated);
        }
        let packet_number_offset = at;
        let mut sample = [0; 16];
        sample.copy_from_slice(&input[packet_number_offset + 4..packet_number_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        let first = input[0] ^ (mask[0] & 0x0f);
        if first & 0x0c != 0 {
            return Err(QuicError::InvalidPacket);
        }
        let packet_number_length = (first as usize & 3) + 1;
        if protected_length < packet_number_length + 16 {
            return Err(QuicError::Truncated);
        }
        let mut truncated = 0u64;
        let mut unprotected_number = [0u8; 4];
        for index in 0..packet_number_length {
            let byte = input[packet_number_offset + index] ^ mask[index + 1];
            unprotected_number[4 - packet_number_length + index] = byte;
            truncated = (truncated << 8) | byte as u64;
        }
        let packet_number =
            reconstruct_packet_number(truncated, packet_number_length, expected_packet_number)?;
        let aad_end = packet_number_offset + packet_number_length;
        let mut aad = Vector::new();
        aad.try_extend_from_slice(&input[..aad_end])
            .map_err(|_| QuicError::Allocation)?;
        aad[0] = first;
        aad[packet_number_offset..aad_end]
            .copy_from_slice(&unprotected_number[4 - packet_number_length..]);
        let encrypted_end = packet_end - 16;
        let encrypted = &input[aad_end..encrypted_end];
        let mut tag = [0; 16];
        tag.copy_from_slice(&input[encrypted_end..packet_end]);
        let mut payload = Vector::new();
        payload
            .try_reserve(encrypted.len())
            .map_err(|_| QuicError::Allocation)?;
        for _ in 0..encrypted.len() {
            payload.push(0);
        }
        if !aes128_gcm_open(
            &keys.key,
            &keys.nonce(packet_number),
            &aad,
            encrypted,
            &tag,
            &mut payload,
        ) {
            return Err(QuicError::Crypto);
        }
        Ok((
            Self {
                destination_id,
                source_id,
                packet_number,
                payload,
            },
            packet_end,
        ))
    }
}

fn reconstruct_packet_number(
    truncated: u64,
    encoded_bytes: usize,
    expected: u64,
) -> Result<u64, QuicError> {
    if !(1..=4).contains(&encoded_bytes) || expected >= (1 << 62) {
        return Err(QuicError::InvalidPacket);
    }
    let window = 1u64 << (encoded_bytes * 8);
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half <= expected && candidate < (1 << 62) - window {
        Ok(candidate + window)
    } else if candidate > expected + half && candidate >= window {
        Ok(candidate - window)
    } else {
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vector<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc9001_initial_secrets() {
        let k = QuicInitialKeys::derive(&hex("8394c8f03e515708"), QuicRole::Client).unwrap();
        assert_eq!(&k.key[..], &hex("1f369613dd76d5467730efcbe3b1a22d")[..]);
        assert_eq!(&k.iv[..], &hex("fa044b2f42a3fd3b46fb255c")[..]);
        assert_eq!(&k.header[..], &hex("9f50449e04a0e810283a1e9933adedd2")[..])
    }
    #[test]
    fn authenticated_packet_history_rejects_replay_and_bounds_sparse_ranges() {
        let mut state = PacketReceiveState::new();
        assert_eq!(state.record(7), Ok(ReceivedPacket::New));
        assert_eq!(state.expected(), 8);
        assert_eq!(state.record(7), Ok(ReceivedPacket::Duplicate));
        assert_eq!(state.record(5), Ok(ReceivedPacket::New));
        assert_eq!(state.expected(), 8);
        assert_eq!(state.record(6), Ok(ReceivedPacket::New));
        assert_eq!(&state.ranges[..], &[(5, 7)]);
        assert_eq!(state.record(5000), Ok(ReceivedPacket::New));
        assert_eq!(state.record(1), Ok(ReceivedPacket::TooOld));
        for number in (5002..5500).step_by(2) {
            assert_eq!(state.record(number), Ok(ReceivedPacket::New));
        }
        assert!(state.ranges.len() <= MAX_RECEIVE_RANGES);
        assert_eq!(state.expected(), 5499);
    }
    #[test]
    fn packet_ack_ranges_cover_authenticated_reordering() {
        let mut state = PacketReceiveState::new();
        for number in [10, 8, 7, 4] {
            assert_eq!(state.record(number), Ok(ReceivedPacket::New));
        }
        assert_eq!(
            state.ack_frame(),
            Some(QuicFrame::Ack {
                largest: 10,
                delay: 0,
                first_range: 0,
                ranges: [(0, 1), (1, 0)].into(),
            })
        );
    }
    #[test]
    fn rfc9369_v2_initial_secrets_and_packet_types() {
        let destination = hex("8394c8f03e515708");
        let client =
            QuicInitialKeys::derive_for(QuicVersion::V2, &destination, QuicRole::Client).unwrap();
        assert_eq!(
            &client.key[..],
            &hex("8b1a0bc121284290a29e0971b5cd045d")[..]
        );
        assert_eq!(&client.iv[..], &hex("91f73e2351d8fa91660e909f")[..]);
        assert_eq!(
            &client.header[..],
            &hex("45b95e15235d6f45a6b19cbcb0294ba9")[..]
        );
        let server =
            QuicInitialKeys::derive_for(QuicVersion::V2, &destination, QuicRole::Server).unwrap();
        assert_eq!(
            &server.key[..],
            &hex("82db637861d55e1d011f19ea71d5d2a7")[..]
        );
        assert_eq!(&server.iv[..], &hex("dd13c276499c0249d3310652")[..]);
        assert_eq!(
            &server.header[..],
            &hex("edf6d05c83121201b436e16877593c3a")[..]
        );

        let packet = InitialPacket {
            destination_id: destination,
            source_id: [1, 2, 3, 4].into(),
            packet_number: 2,
            payload: [1, 2, 3, 4, 5].into(),
        };
        let wire = packet.seal_for(QuicVersion::V2, &client).unwrap();
        assert_eq!(&wire[1..5], &QuicVersion::V2.wire().to_be_bytes());
        assert_eq!(wire[0] & 0xf0, 0xd0);
        assert_eq!(
            InitialPacket::open_for(QuicVersion::V2, &wire, &client, 2)
                .unwrap()
                .0,
            packet
        );
        assert!(InitialPacket::open(&wire, &client, 2).is_err());
    }
    #[test]
    fn frames_round_trip_and_reject_truncation() {
        let frames = [
            QuicFrame::Ping,
            QuicFrame::Ack {
                largest: 20,
                delay: 3,
                first_range: 2,
                ranges: [(1, 3)].into(),
            },
            QuicFrame::Crypto {
                offset: 4,
                data: [b't', b'l', b's'].into(),
            },
            QuicFrame::NewConnectionId {
                sequence: 1,
                retire_prior_to: 0,
                connection_id: [9, 8, 7, 6].into(),
                reset_token: [5; 16],
            },
            QuicFrame::PathChallenge([7; 8]),
        ];
        let mut wire = Vector::new();
        for f in &frames {
            f.encode(&mut wire).unwrap()
        }
        let mut at = 0;
        for expected in frames {
            assert_eq!(QuicFrame::decode(&wire, &mut at).unwrap(), expected)
        }
        assert_eq!(at, wire.len());
        let mut at = 0;
        assert!(QuicFrame::decode(&[6, 0, 4, 1], &mut at).is_err())
    }
    #[test]
    fn initial_packet_seals_deterministically() {
        let keys = QuicInitialKeys::derive(&[1, 2, 3, 4], QuicRole::Client).unwrap();
        let p = InitialPacket {
            destination_id: [1, 2, 3, 4].into(),
            source_id: [9, 8, 7, 6].into(),
            packet_number: 7,
            payload: [1, 2, 3, 4, 5].into(),
        };
        let a = p.seal(&keys).unwrap();
        let b = p.seal(&keys).unwrap();
        assert_eq!(a, b);
        assert!(a.len() > p.payload.len() + 16);
        let (opened, used) = InitialPacket::open(&a, &keys, 7).unwrap();
        assert_eq!(used, a.len());
        assert_eq!(opened, p);
        let mut corrupted = a.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert_eq!(
            InitialPacket::open(&corrupted, &keys, 7),
            Err(QuicError::Crypto)
        );
    }
    #[test]
    fn transport_parameters_reject_duplicates_and_bad_datagrams() {
        let mut parameters = QuicTransportParameters::default();
        parameters.chosen_version = Some(QuicVersion::V2.wire());
        parameters.available_versions = [QuicVersion::V2.wire(), QuicVersion::V1.wire()].into();
        let wire = parameters.encode().unwrap();
        assert_eq!(QuicTransportParameters::decode(&wire).unwrap(), parameters);
        let mut duplicate = wire.clone();
        duplicate.try_extend_from_slice(&[3, 1, 63]).unwrap();
        assert!(QuicTransportParameters::decode(&duplicate).is_err());
        let mut greased = wire.clone();
        greased.try_extend_from_slice(&[0x40, 0x1f, 0]).unwrap();
        assert_eq!(
            QuicTransportParameters::decode(&greased).unwrap(),
            parameters
        );
        assert!(QuicRecovery::new(1199).is_err())
    }
    #[test]
    fn new_reno_bounds_flight_and_halves_on_loss() {
        let mut recovery = QuicRecovery::new(1200).unwrap();
        let initial = recovery.congestion_window;
        let packet = SentPacket {
            number: 1,
            sent_micros: 1000,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
        };
        recovery.on_sent(packet).unwrap();
        assert_eq!(recovery.bytes_in_flight, 1200);
        recovery.on_ack(packet, 101_000, 0).unwrap();
        assert_eq!(recovery.bytes_in_flight, 0);
        assert!(recovery.congestion_window > initial);
        let packet = SentPacket {
            number: 2,
            sent_micros: 200_000,
            ..packet
        };
        recovery.on_sent(packet).unwrap();
        recovery.on_loss(packet, 300_000);
        assert!(recovery.congestion_window >= 2400);
        assert_eq!(recovery.slow_start_threshold, recovery.congestion_window)
    }
    #[test]
    fn short_packets_authenticate_and_streams_reassemble() {
        let keys = QuicInitialKeys::from_traffic_secret(&[7; 32]).unwrap();
        let packet = ShortPacket {
            destination_id: [1, 2, 3, 4].into(),
            packet_number: 55,
            key_phase: false,
            payload: [9, 8, 7, 6, 5].into(),
        };
        let wire = packet.seal(&keys).unwrap();
        assert_eq!(ShortPacket::open(&wire, 4, &keys, 55).unwrap(), packet);
        let mut bad = wire.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            ShortPacket::open(&bad, 4, &keys, 55),
            Err(QuicError::Crypto)
        );
        let mut stream = QuicStreamAssembler::new(16);
        stream.insert(3, b"lo", true).unwrap();
        assert_eq!(stream.contiguous(), b"");
        stream.insert(0, b"hel", false).unwrap();
        assert_eq!(stream.contiguous(), b"hello");
        assert!(stream.is_finished());
        assert_eq!(stream.insert(1, b"X", false), Err(QuicError::InvalidFrame));
        stream.consume(2).unwrap();
        assert_eq!(stream.contiguous(), b"llo");
    }
    #[test]
    fn stream_assembler_does_not_allocate_to_sparse_high_offset() {
        let mut stream = QuicStreamAssembler::new(16 * 1024 * 1024 + 1);
        assert_eq!(
            stream.insert(16 * 1024 * 1024, &[1], false),
            Err(QuicError::Limit)
        );
        assert!(stream.bytes.is_empty());
        assert!(stream.chunks.is_empty());

        stream.insert(1024, &[3], false).unwrap();
        assert!(stream.bytes.is_empty());
        assert_eq!(stream.chunks.len(), 1);
        assert_eq!(&stream.chunks[0].bytes[..], &[3]);
        let prefix = [9; 1024];
        stream.insert(0, &prefix, false).unwrap();
        assert_eq!(stream.contiguous().len(), 1025);
        assert_eq!(stream.contiguous()[1024], 3);
    }
    #[test]
    fn handshake_packets_and_minimum_initial_datagrams() {
        let packet = HandshakePacket {
            destination_id: [1, 2, 3, 4].into(),
            source_id: [5, 6, 7, 8].into(),
            packet_number: 12,
            payload: (*b"encrypted handshake").into(),
        };
        for version in [QuicVersion::V1, QuicVersion::V2] {
            let keys = QuicInitialKeys::from_traffic_secret_for(version, &[9; 32]).unwrap();
            let wire = packet.seal_for(version, &keys).unwrap();
            assert_eq!(
                HandshakePacket::open_for(version, &wire, &keys, 12)
                    .unwrap()
                    .0,
                packet
            );
            assert_eq!(wire[0] & 0xf0, version.handshake_type());
        }
        let initial_keys = QuicInitialKeys::derive(&[1, 2, 3, 4], QuicRole::Client).unwrap();
        let initial = InitialPacket {
            destination_id: [1, 2, 3, 4].into(),
            source_id: [9, 8, 7, 6].into(),
            packet_number: 0,
            payload: [1].into(),
        };
        assert!(initial.seal_padded(&initial_keys).unwrap().len() >= 1200);
    }
    #[test]
    fn connection_state_enforces_amplification_flow_and_path_validation() {
        let parameters = QuicTransportParameters {
            initial_max_data: 8,
            initial_max_stream_data_bidi_remote: 4,
            initial_max_streams_bidi: 1,
            ..QuicTransportParameters::default()
        };
        let mut server = QuicConnectionState::new(QuicRole::Server, &parameters);
        server.on_datagram_received(100).unwrap();
        server.authorize_datagram_send(300).unwrap();
        assert_eq!(
            server.authorize_datagram_send(1),
            Err(QuicError::FlowControl)
        );
        let challenge = [3; 8];
        assert_eq!(
            server.start_path_validation(challenge),
            QuicFrame::PathChallenge(challenge)
        );
        assert_eq!(
            server.on_path_response([4; 8]),
            Err(QuicError::ProtocolViolation)
        );
        server.on_path_response(challenge).unwrap();
        server.authorize_datagram_send(1000).unwrap();
        server.activate().unwrap();
        assert_eq!(server.open_bidi_stream().unwrap(), 1);
        assert_eq!(server.open_bidi_stream(), Err(QuicError::FlowControl));
        server.authorize_stream_send(4).unwrap();
        assert_eq!(server.authorize_stream_send(5), Err(QuicError::FlowControl));
    }
}
