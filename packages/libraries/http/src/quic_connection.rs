use mrml_runtime::{Instant, SocketAddress, TcpStream, UdpSocket, Vector};
use mrml_tls::{QuicTlsClientHandshake, QuicTlsServerHandshake, TlsServerConfig};

use crate::quic::initial_destination_id;
use crate::{
    HandshakePacket, InitialPacket, QuicConnectionState, QuicError, QuicFrame, QuicInitialKeys,
    QuicRecovery, QuicRole, QuicStreamAssembler, QuicTransportParameters, SentPacket, ShortPacket,
};

const CRYPTO_CHUNK: usize = 900;
const CONNECTION_ID_LENGTH: usize = 8;

fn random_connection_id() -> Result<Vector<u8>, QuicError> {
    let mut bytes = [0; CONNECTION_ID_LENGTH];
    mrml_runtime::fill_random(&mut bytes).map_err(|_| QuicError::Crypto)?;
    Ok(bytes.into())
}

fn crypto_payload(offset: usize, bytes: &[u8]) -> Result<Vector<u8>, QuicError> {
    let mut payload = Vector::new();
    let mut data = Vector::new();
    data.try_extend_from_slice(bytes)
        .map_err(|_| QuicError::Allocation)?;
    QuicFrame::Crypto {
        offset: offset as u64,
        data,
    }
    .encode(&mut payload)?;
    Ok(payload)
}

fn insert_crypto_frames(
    payload: &[u8],
    assembler: &mut QuicStreamAssembler,
) -> Result<(), QuicError> {
    let mut at = 0;
    while at < payload.len() {
        match QuicFrame::decode(payload, &mut at)? {
            QuicFrame::Crypto { offset, data } => assembler.insert(offset, &data, false)?,
            QuicFrame::Padding | QuicFrame::Ping | QuicFrame::Ack { .. } => {}
            QuicFrame::ConnectionClose {
                code, frame_type, ..
            } => {
                return Err(QuicError::PeerClosed { code, frame_type });
            }
            _ => return Err(QuicError::ProtocolViolation),
        }
    }
    Ok(())
}

fn handshake_message(bytes: &[u8], at: usize) -> Result<Option<&[u8]>, QuicError> {
    if bytes.len().saturating_sub(at) < 4 {
        return Ok(None);
    }
    let length =
        ((bytes[at + 1] as usize) << 16) | ((bytes[at + 2] as usize) << 8) | bytes[at + 3] as usize;
    let end = at
        .checked_add(4)
        .and_then(|value| value.checked_add(length))
        .ok_or(QuicError::Limit)?;
    if end > bytes.len() {
        return Ok(None);
    }
    Ok(Some(&bytes[at..end]))
}

pub struct QuicConnection {
    socket: UdpSocket,
    peer: SocketAddress,
    local_id: Vector<u8>,
    peer_id: Vector<u8>,
    read_keys: QuicInitialKeys,
    write_keys: QuicInitialKeys,
    state: QuicConnectionState,
    next_packet_number: u64,
    expected_packet_number: u64,
    recovery: QuicRecovery,
    sent: Vector<PendingPacket>,
    epoch: Instant,
    candidate_peer: Option<SocketAddress>,
    peer_ack_delay_exponent: u8,
    peer_max_ack_delay_micros: u64,
    pending_frames: Vector<QuicFrame>,
}

struct PendingPacket {
    metadata: SentPacket,
    payload: Vector<u8>,
    attempts: u8,
}

impl QuicConnection {
    pub fn state(&self) -> &QuicConnectionState {
        &self.state
    }

    pub fn open_bidi_stream(&mut self) -> Result<u64, QuicError> {
        self.state.open_bidi_stream()
    }

    pub fn open_uni_stream(&mut self) -> Result<u64, QuicError> {
        self.state.open_uni_stream()
    }

    pub fn send_frames(&mut self, frames: &[QuicFrame]) -> Result<(), QuicError> {
        let mut payload = Vector::new();
        let mut ack_eliciting = false;
        for frame in frames {
            if let QuicFrame::Stream { data, .. } = frame {
                self.state.authorize_stream_send(data.len())?;
            }
            ack_eliciting |= !matches!(frame, QuicFrame::Padding | QuicFrame::Ack { .. });
            frame.encode(&mut payload)?;
        }
        self.send_payload(payload, ack_eliciting, 0)
    }

    fn now_micros(&self) -> u64 {
        self.epoch.elapsed().as_micros().min(u64::MAX as u128) as u64
    }

    fn send_payload(
        &mut self,
        payload: Vector<u8>,
        ack_eliciting: bool,
        attempts: u8,
    ) -> Result<(), QuicError> {
        let packet = ShortPacket {
            destination_id: self.peer_id.clone(),
            packet_number: self.next_packet_number,
            key_phase: false,
            payload: payload.clone(),
        }
        .seal(&self.write_keys)?;
        if ack_eliciting && !self.recovery.can_send(packet.len() as u64) {
            return Err(QuicError::FlowControl);
        }
        self.state.authorize_datagram_send(packet.len())?;
        if self
            .socket
            .send_to(&packet, self.peer)
            .map_err(|_| QuicError::Io)?
            != packet.len()
        {
            return Err(QuicError::Io);
        }
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(QuicError::Limit)?;
        if ack_eliciting {
            let metadata = SentPacket {
                number: self.next_packet_number - 1,
                sent_micros: self.now_micros(),
                bytes: packet.len() as u64,
                ack_eliciting: true,
                in_flight: true,
            };
            self.recovery.on_sent(metadata)?;
            self.sent
                .try_push(PendingPacket {
                    metadata,
                    payload,
                    attempts,
                })
                .map_err(|_| QuicError::Allocation)?;
        }
        Ok(())
    }

    fn send_path_frame(&mut self, peer: SocketAddress, frame: QuicFrame) -> Result<(), QuicError> {
        let mut payload = Vector::new();
        frame.encode(&mut payload)?;
        let packet = ShortPacket {
            destination_id: self.peer_id.clone(),
            packet_number: self.next_packet_number,
            key_phase: false,
            payload,
        }
        .seal(&self.write_keys)?;
        if self
            .socket
            .send_to(&packet, peer)
            .map_err(|_| QuicError::Io)?
            != packet.len()
        {
            return Err(QuicError::Io);
        }
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(QuicError::Limit)?;
        Ok(())
    }

    pub fn receive_frames(&mut self) -> Result<Vector<QuicFrame>, QuicError> {
        if !self.pending_frames.is_empty() {
            return Ok(core::mem::take(&mut self.pending_frames));
        }
        let mut datagram = [0; 65_527];
        let (amount, peer) = loop {
            match self.socket.receive_from(&mut datagram) {
                Ok(value) => break value,
                Err(_) => {
                    let Some(index) = self.sent.iter().rposition(|packet| packet.attempts < 3)
                    else {
                        return Err(QuicError::Io);
                    };
                    let lost = self.sent.remove(index);
                    self.recovery.on_loss(lost.metadata, self.now_micros());
                    self.send_payload(lost.payload, true, lost.attempts + 1)?;
                }
            }
        };
        self.state.on_datagram_received(amount)?;
        let packet = ShortPacket::open(
            &datagram[..amount],
            self.local_id.len(),
            &self.read_keys,
            self.expected_packet_number,
        )?;
        if packet.destination_id != self.local_id {
            return Err(QuicError::InvalidPacket);
        }
        self.expected_packet_number = packet
            .packet_number
            .checked_add(1)
            .ok_or(QuicError::Limit)?;
        let mut frames = Vector::new();
        let mut at = 0;
        let mut acknowledge = false;
        while at < packet.payload.len() {
            let frame = QuicFrame::decode(&packet.payload, &mut at)?;
            if let QuicFrame::Ack {
                largest,
                delay,
                first_range,
                ref ranges,
                ..
            } = frame
            {
                let mut intervals = Vector::new();
                let mut smallest = largest - first_range;
                intervals
                    .try_push((smallest, largest))
                    .map_err(|_| QuicError::Allocation)?;
                for (gap, range) in ranges {
                    let range_largest = smallest - gap - 2;
                    smallest = range_largest - range;
                    intervals
                        .try_push((smallest, range_largest))
                        .map_err(|_| QuicError::Allocation)?;
                }
                let mut acknowledged_indexes = Vector::new();
                for (index, pending) in self.sent.iter().enumerate() {
                    if intervals
                        .iter()
                        .any(|(start, end)| (*start..=*end).contains(&pending.metadata.number))
                    {
                        acknowledged_indexes
                            .try_push(index)
                            .map_err(|_| QuicError::Allocation)?;
                    }
                }
                for index in acknowledged_indexes.into_iter().rev() {
                    let acknowledged = self.sent.remove(index);
                    let ack_delay = delay
                        .checked_shl(self.peer_ack_delay_exponent as u32)
                        .unwrap_or(u64::MAX)
                        .min(self.peer_max_ack_delay_micros);
                    self.recovery
                        .on_ack(acknowledged.metadata, self.now_micros(), ack_delay)?;
                }
            } else if !matches!(frame, QuicFrame::Padding) {
                acknowledge = true;
            }
            frames.try_push(frame).map_err(|_| QuicError::Allocation)?;
        }
        if peer != self.peer {
            if self.candidate_peer != Some(peer) {
                let mut challenge = [0; 8];
                mrml_runtime::fill_random(&mut challenge).map_err(|_| QuicError::Crypto)?;
                let frame = self.state.start_path_validation(challenge);
                self.candidate_peer = Some(peer);
                self.send_path_frame(peer, frame)?;
                return Ok(Vector::new());
            }
            let response = frames.iter().find_map(|frame| match frame {
                QuicFrame::PathResponse(value) => Some(*value),
                _ => None,
            });
            self.state
                .on_path_response(response.ok_or(QuicError::UnexpectedPeer)?)?;
            self.peer = peer;
            self.candidate_peer = None;
            while let Some(index) = frames
                .iter()
                .position(|frame| matches!(frame, QuicFrame::PathResponse(_)))
            {
                frames.remove(index);
            }
        }
        if let Some(challenge) = frames.iter().find_map(|frame| match frame {
            QuicFrame::PathChallenge(value) => Some(*value),
            _ => None,
        }) {
            self.send_path_frame(peer, QuicFrame::PathResponse(challenge))?;
        }
        if acknowledge {
            let mut acknowledgement = Vector::new();
            QuicFrame::Ack {
                largest: packet.packet_number,
                delay: 0,
                first_range: 0,
                ranges: Vector::new(),
            }
            .encode(&mut acknowledgement)?;
            self.send_payload(acknowledgement, false, 0)?;
        }
        Ok(frames)
    }
}

pub struct QuicClientConnection;
impl QuicClientConnection {
    pub fn connect(host: &str, port: u16) -> Result<QuicConnection, QuicError> {
        let peer = SocketAddress {
            ip: TcpStream::resolve_host(host).map_err(|_| QuicError::Io)?,
            port,
        };
        let socket = UdpSocket::bind([0, 0, 0, 0], 0).map_err(|_| QuicError::Io)?;
        socket
            .set_read_timeout_millis(30_000)
            .map_err(|_| QuicError::Io)?;
        socket
            .set_write_timeout_millis(30_000)
            .map_err(|_| QuicError::Io)?;
        let destination_id = random_connection_id()?;
        let source_id = random_connection_id()?;
        let mut local_parameters = QuicTransportParameters::default();
        local_parameters.initial_source_connection_id = source_id.clone();
        let encoded_parameters = local_parameters.encode()?;
        let (mut tls, client_hello) =
            QuicTlsClientHandshake::new(host, &encoded_parameters).map_err(|_| QuicError::Tls)?;
        let client_initial = QuicInitialKeys::derive(&destination_id, QuicRole::Client)?;
        let server_initial = QuicInitialKeys::derive(&destination_id, QuicRole::Server)?;
        for (packet_number, chunk) in client_hello.chunks(CRYPTO_CHUNK).enumerate() {
            let packet = InitialPacket {
                destination_id: destination_id.clone(),
                source_id: source_id.clone(),
                packet_number: packet_number as u64,
                payload: crypto_payload(packet_number * CRYPTO_CHUNK, chunk)?,
            }
            .seal_padded(&client_initial)?;
            socket.send_to(&packet, peer).map_err(|_| QuicError::Io)?;
        }
        let mut server_initial_crypto = QuicStreamAssembler::new(64 * 1024);
        let mut expected_initial = 0;
        let mut server_id = None;
        let handshake_secrets = loop {
            let mut datagram = [0; 65_527];
            let (amount, from) = socket
                .receive_from(&mut datagram)
                .map_err(|_| QuicError::Io)?;
            if from != peer {
                return Err(QuicError::UnexpectedPeer);
            }
            let (packet, _) =
                InitialPacket::open(&datagram[..amount], &server_initial, expected_initial)?;
            if packet.destination_id != source_id {
                return Err(QuicError::InvalidPacket);
            }
            expected_initial = packet.packet_number + 1;
            if server_id.is_none() {
                server_id = Some(packet.source_id.clone());
            } else if server_id.as_ref() != Some(&packet.source_id) {
                return Err(QuicError::ConnectionId);
            }
            insert_crypto_frames(&packet.payload, &mut server_initial_crypto)?;
            if let Some(message) = handshake_message(server_initial_crypto.contiguous(), 0)? {
                break tls
                    .receive_server_hello(message)
                    .map_err(|_| QuicError::Tls)?;
            }
        };
        let read_handshake = QuicInitialKeys::from_traffic_secret(&handshake_secrets.server)?;
        let write_handshake = QuicInitialKeys::from_traffic_secret(&handshake_secrets.client)?;
        let mut handshake_crypto = QuicStreamAssembler::new(1024 * 1024);
        let mut handshake_at = 0;
        let mut expected_handshake = 0;
        let application = 'application: loop {
            let mut datagram = [0; 65_527];
            let (amount, from) = socket
                .receive_from(&mut datagram)
                .map_err(|_| QuicError::Io)?;
            if from != peer {
                return Err(QuicError::UnexpectedPeer);
            }
            let (packet, _) =
                HandshakePacket::open(&datagram[..amount], &read_handshake, expected_handshake)?;
            expected_handshake = packet.packet_number + 1;
            insert_crypto_frames(&packet.payload, &mut handshake_crypto)?;
            while let Some(message) =
                handshake_message(handshake_crypto.contiguous(), handshake_at)?
            {
                handshake_at += message.len();
                if let Some(application) =
                    tls.receive_handshake(message).map_err(|_| QuicError::Tls)?
                {
                    break 'application application;
                }
            }
        };
        let peer_parameters =
            QuicTransportParameters::decode(&application.peer_transport_parameters)?;
        let peer_id = server_id.ok_or(QuicError::ProtocolViolation)?;
        if peer_parameters.original_destination_connection_id.as_ref() != Some(&destination_id)
            || peer_parameters.initial_source_connection_id != peer_id
        {
            return Err(QuicError::TransportParameter);
        }
        let mut finished_payload = crypto_payload(0, &application.client_finished)?;
        QuicFrame::Ack {
            largest: expected_handshake.saturating_sub(1),
            delay: 0,
            first_range: expected_handshake.saturating_sub(1),
            ranges: Vector::new(),
        }
        .encode(&mut finished_payload)?;
        let finished = HandshakePacket {
            destination_id: peer_id.clone(),
            source_id: source_id.clone(),
            packet_number: 0,
            payload: finished_payload,
        }
        .seal(&write_handshake)?;
        socket.send_to(&finished, peer).map_err(|_| QuicError::Io)?;
        let mut datagram = [0; 65_527];
        let (amount, from) = socket
            .receive_from(&mut datagram)
            .map_err(|_| QuicError::Io)?;
        if from != peer {
            return Err(QuicError::UnexpectedPeer);
        }
        let (handshake_ack, _) =
            HandshakePacket::open(&datagram[..amount], &read_handshake, expected_handshake)?;
        let mut at = 0;
        let mut finished_acknowledged = false;
        while at < handshake_ack.payload.len() {
            match QuicFrame::decode(&handshake_ack.payload, &mut at)? {
                QuicFrame::Padding | QuicFrame::Ping => {}
                QuicFrame::Ack {
                    largest,
                    first_range,
                    ..
                } if largest == 0 && first_range == 0 => {
                    finished_acknowledged = true
                }
                _ => return Err(QuicError::ProtocolViolation),
            }
        }
        if !finished_acknowledged {
            return Err(QuicError::HandshakeConfirmation);
        }
        let state = QuicConnectionState::new(QuicRole::Client, &peer_parameters);
        let recovery = QuicRecovery::new(peer_parameters.max_udp_payload_size)?;
        let mut connection = QuicConnection {
            socket,
            peer,
            local_id: source_id,
            peer_id,
            read_keys: QuicInitialKeys::from_traffic_secret(&application.server)?,
            write_keys: QuicInitialKeys::from_traffic_secret(&application.client)?,
            state,
            next_packet_number: 0,
            expected_packet_number: 0,
            recovery,
            sent: Vector::new(),
            epoch: Instant::now(),
            candidate_peer: None,
            peer_ack_delay_exponent: peer_parameters.ack_delay_exponent as u8,
            peer_max_ack_delay_micros: peer_parameters.max_ack_delay_ms * 1000,
            pending_frames: Vector::new(),
        };
        let mut early_frames = Vector::new();
        loop {
            let mut frames = connection.receive_frames()?;
            if let Some(index) = frames
                .iter()
                .position(|frame| *frame == QuicFrame::HandshakeDone)
            {
                frames.remove(index);
                for frame in frames {
                    early_frames
                        .try_push(frame)
                        .map_err(|_| QuicError::Allocation)?;
                }
                break;
            }
            for frame in frames {
                early_frames
                    .try_push(frame)
                    .map_err(|_| QuicError::Allocation)?;
            }
        }
        connection.pending_frames = early_frames;
        connection
            .state
            .activate()
            .map_err(|_| QuicError::HandshakeConfirmation)?;
        Ok(connection)
    }
}

pub struct QuicServerListener {
    socket: UdpSocket,
    parameters: QuicTransportParameters,
}
impl QuicServerListener {
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, QuicError> {
        let socket = UdpSocket::bind(ip, port).map_err(|_| QuicError::Io)?;
        socket
            .set_read_timeout_millis(30_000)
            .map_err(|_| QuicError::Io)?;
        socket
            .set_write_timeout_millis(30_000)
            .map_err(|_| QuicError::Io)?;
        Ok(Self {
            socket,
            parameters: QuicTransportParameters::default(),
        })
    }
    pub fn local_port(&self) -> Result<u16, QuicError> {
        self.socket.local_port().map_err(|_| QuicError::Io)
    }
    pub fn accept(self, config: &TlsServerConfig) -> Result<QuicConnection, QuicError> {
        let mut datagram = [0; 65_527];
        let mut initial_crypto = QuicStreamAssembler::new(64 * 1024);
        let mut initial_keys = None;
        let mut original_destination_id = None;
        let mut client_id = None;
        let mut peer = None;
        let mut expected_initial = 0;
        let mut state = QuicConnectionState::new(QuicRole::Server, &self.parameters);
        let client_hello = loop {
            let (amount, from) = self
                .socket
                .receive_from(&mut datagram)
                .map_err(|_| QuicError::Io)?;
            if amount < 1200 || peer.is_some_and(|known| known != from) {
                return Err(QuicError::ProtocolViolation);
            }
            peer = Some(from);
            state.on_datagram_received(amount)?;
            if initial_keys.is_none() {
                let id = initial_destination_id(&datagram[..amount])?;
                initial_keys = Some(QuicInitialKeys::derive(&id, QuicRole::Client)?);
                original_destination_id = Some(id);
            }
            let (packet, _) = InitialPacket::open(
                &datagram[..amount],
                initial_keys.as_ref().ok_or(QuicError::Crypto)?,
                expected_initial,
            )?;
            expected_initial = packet.packet_number + 1;
            if client_id.is_none() {
                client_id = Some(packet.source_id.clone());
            } else if client_id.as_ref() != Some(&packet.source_id) {
                return Err(QuicError::ProtocolViolation);
            }
            insert_crypto_frames(&packet.payload, &mut initial_crypto)?;
            if let Some(message) = handshake_message(initial_crypto.contiguous(), 0)? {
                let mut owned = Vector::new();
                owned
                    .try_extend_from_slice(message)
                    .map_err(|_| QuicError::Allocation)?;
                break owned;
            }
        };
        let peer = peer.ok_or(QuicError::ProtocolViolation)?;
        let client_id = client_id.ok_or(QuicError::ProtocolViolation)?;
        let original_destination_id =
            original_destination_id.ok_or(QuicError::ProtocolViolation)?;
        let server_id = random_connection_id()?;
        let mut local_parameters = self.parameters.clone();
        local_parameters.original_destination_connection_id = Some(original_destination_id.clone());
        local_parameters.initial_source_connection_id = server_id.clone();
        let encoded_parameters = local_parameters.encode()?;
        let (mut tls, flight) =
            QuicTlsServerHandshake::accept(&client_hello, &encoded_parameters, config)
                .map_err(|_| QuicError::Tls)?;
        let server_initial = QuicInitialKeys::derive(&original_destination_id, QuicRole::Server)?;
        for (number, chunk) in flight.server_hello.chunks(CRYPTO_CHUNK).enumerate() {
            let mut payload = crypto_payload(number * CRYPTO_CHUNK, chunk)?;
            if number == 0 {
                QuicFrame::Ack {
                    largest: expected_initial.saturating_sub(1),
                    delay: 0,
                    first_range: expected_initial.saturating_sub(1),
                    ranges: Vector::new(),
                }
                .encode(&mut payload)?;
            }
            let packet = InitialPacket {
                destination_id: client_id.clone(),
                source_id: server_id.clone(),
                packet_number: number as u64,
                payload,
            }
            .seal(&server_initial)?;
            state.authorize_datagram_send(packet.len())?;
            self.socket
                .send_to(&packet, peer)
                .map_err(|_| QuicError::Io)?;
        }
        let read_handshake = QuicInitialKeys::from_traffic_secret(&flight.client_handshake_secret)?;
        let write_handshake =
            QuicInitialKeys::from_traffic_secret(&flight.server_handshake_secret)?;
        let mut handshake_bytes = Vector::new();
        for message in &flight.handshake_messages {
            handshake_bytes
                .try_extend_from_slice(message)
                .map_err(|_| QuicError::Allocation)?;
        }
        let server_handshake_packets = handshake_bytes.chunks(CRYPTO_CHUNK).len();
        for (number, chunk) in handshake_bytes.chunks(CRYPTO_CHUNK).enumerate() {
            let packet = HandshakePacket {
                destination_id: client_id.clone(),
                source_id: server_id.clone(),
                packet_number: number as u64,
                payload: crypto_payload(number * CRYPTO_CHUNK, chunk)?,
            }
            .seal(&write_handshake)?;
            state.authorize_datagram_send(packet.len())?;
            self.socket
                .send_to(&packet, peer)
                .map_err(|_| QuicError::Io)?;
        }
        let (amount, from) = self
            .socket
            .receive_from(&mut datagram)
            .map_err(|_| QuicError::Io)?;
        if from != peer {
            return Err(QuicError::ProtocolViolation);
        }
        state.on_datagram_received(amount)?;
        let (finished, _) = HandshakePacket::open(&datagram[..amount], &read_handshake, 0)?;
        let mut finished_crypto = QuicStreamAssembler::new(64);
        insert_crypto_frames(&finished.payload, &mut finished_crypto)?;
        let message =
            handshake_message(finished_crypto.contiguous(), 0)?.ok_or(QuicError::Truncated)?;
        tls.receive_client_finished(message)
            .map_err(|_| QuicError::Tls)?;
        let mut handshake_ack_payload = Vector::new();
        QuicFrame::Ack {
            largest: finished.packet_number,
            delay: 0,
            first_range: 0,
            ranges: Vector::new(),
        }
        .encode(&mut handshake_ack_payload)?;
        let handshake_ack = HandshakePacket {
            destination_id: client_id.clone(),
            source_id: server_id.clone(),
            packet_number: server_handshake_packets as u64,
            payload: handshake_ack_payload,
        }
        .seal(&write_handshake)?;
        state.authorize_datagram_send(handshake_ack.len())?;
        self.socket
            .send_to(&handshake_ack, peer)
            .map_err(|_| QuicError::Io)?;
        let peer_parameters = QuicTransportParameters::decode(&flight.peer_transport_parameters)?;
        if peer_parameters.original_destination_connection_id.is_some()
            || peer_parameters.initial_source_connection_id != client_id
        {
            return Err(QuicError::ProtocolViolation);
        }
        state = QuicConnectionState::new(QuicRole::Server, &peer_parameters);
        state.validate_address();
        state.activate()?;
        let recovery = QuicRecovery::new(peer_parameters.max_udp_payload_size)?;
        let mut connection = QuicConnection {
            socket: self.socket,
            peer,
            local_id: server_id,
            peer_id: client_id,
            read_keys: QuicInitialKeys::from_traffic_secret(&flight.client_application_secret)?,
            write_keys: QuicInitialKeys::from_traffic_secret(&flight.server_application_secret)?,
            state,
            next_packet_number: 0,
            expected_packet_number: 0,
            recovery,
            sent: Vector::new(),
            epoch: Instant::now(),
            candidate_peer: None,
            peer_ack_delay_exponent: peer_parameters.ack_delay_exponent as u8,
            peer_max_ack_delay_micros: peer_parameters.max_ack_delay_ms * 1000,
            pending_frames: Vector::new(),
        };
        connection.send_frames(&[QuicFrame::HandshakeDone])?;
        Ok(connection)
    }
}
