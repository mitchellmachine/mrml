use mrml_runtime::{SocketAddress, TcpStream, UdpSocket, Vector};
use mrml_tls::{QuicTlsClientHandshake, QuicTlsServerHandshake, TlsServerConfig};

use crate::quic::initial_destination_id;
use crate::{
    HandshakePacket, InitialPacket, QuicConnectionState, QuicError, QuicFrame, QuicInitialKeys,
    QuicRole, QuicStreamAssembler, QuicTransportParameters, ShortPacket,
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
            QuicFrame::Padding | QuicFrame::Ack { .. } => {}
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
}

impl QuicConnection {
    pub fn state(&self) -> &QuicConnectionState {
        &self.state
    }

    pub fn open_bidi_stream(&mut self) -> Result<u64, QuicError> {
        self.state.open_bidi_stream()
    }

    pub fn send_frames(&mut self, frames: &[QuicFrame]) -> Result<(), QuicError> {
        let mut payload = Vector::new();
        for frame in frames {
            if let QuicFrame::Stream { data, .. } = frame {
                self.state.authorize_stream_send(data.len())?;
            }
            frame.encode(&mut payload)?;
        }
        let packet = ShortPacket {
            destination_id: self.peer_id.clone(),
            packet_number: self.next_packet_number,
            key_phase: false,
            payload,
        }
        .seal(&self.write_keys)?;
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
        Ok(())
    }

    pub fn receive_frames(&mut self) -> Result<Vector<QuicFrame>, QuicError> {
        let mut datagram = [0; 65_527];
        let (amount, peer) = self
            .socket
            .receive_from(&mut datagram)
            .map_err(|_| QuicError::Io)?;
        if peer != self.peer {
            return Err(QuicError::ProtocolViolation);
        }
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
        while at < packet.payload.len() {
            frames
                .try_push(QuicFrame::decode(&packet.payload, &mut at)?)
                .map_err(|_| QuicError::Allocation)?;
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
        let local_parameters = QuicTransportParameters::default();
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
                return Err(QuicError::ProtocolViolation);
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
                return Err(QuicError::ProtocolViolation);
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
                return Err(QuicError::ProtocolViolation);
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
        let finished = HandshakePacket {
            destination_id: peer_id.clone(),
            source_id: source_id.clone(),
            packet_number: 0,
            payload: crypto_payload(0, &application.client_finished)?,
        }
        .seal(&write_handshake)?;
        socket.send_to(&finished, peer).map_err(|_| QuicError::Io)?;
        let state = QuicConnectionState::new(QuicRole::Client, &peer_parameters);
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
        };
        let frames = connection.receive_frames()?;
        if !frames
            .iter()
            .any(|frame| *frame == QuicFrame::HandshakeDone)
        {
            return Err(QuicError::ProtocolViolation);
        }
        connection.state.activate()?;
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
        let encoded_parameters = self.parameters.encode()?;
        let (mut tls, flight) =
            QuicTlsServerHandshake::accept(&client_hello, &encoded_parameters, config)
                .map_err(|_| QuicError::Tls)?;
        let server_initial = QuicInitialKeys::derive(&original_destination_id, QuicRole::Server)?;
        for (number, chunk) in flight.server_hello.chunks(CRYPTO_CHUNK).enumerate() {
            let packet = InitialPacket {
                destination_id: client_id.clone(),
                source_id: server_id.clone(),
                packet_number: number as u64,
                payload: crypto_payload(number * CRYPTO_CHUNK, chunk)?,
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
        let peer_parameters = QuicTransportParameters::decode(&flight.peer_transport_parameters)?;
        state = QuicConnectionState::new(QuicRole::Server, &peer_parameters);
        state.validate_address();
        state.activate()?;
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
        };
        connection.send_frames(&[QuicFrame::HandshakeDone])?;
        Ok(connection)
    }
}
