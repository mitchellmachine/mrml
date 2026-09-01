use mrml_runtime::{SocketAddress, UdpSocket, Vector};

use crate::quic::{
    PacketReceiveState, ReceivedPacket, initial_token, initial_version_and_destination_id,
};
use crate::quic_retry::{
    QuicAdmissionController, QuicAdmissionDecision, QuicRetryPurpose, QuicRetryTokenManager,
};
use crate::{QuicError, QuicVersion};

const MAX_DATAGRAM: usize = 65_527;
const MAX_CONNECTION_ID: usize = 20;
const MAX_IDS_PER_CONNECTION: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicConnectionHandle(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPathClassification {
    Validated,
    Candidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicEndpointRoute {
    Handshake(QuicConnectionHandle),
    Established {
        connection: QuicConnectionHandle,
        path: QuicPathClassification,
    },
    NewInitial {
        version: QuicVersion,
        original_destination_id: Vector<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicEndpointDatagram {
    pub peer: SocketAddress,
    pub route: QuicEndpointRoute,
    pub bytes: Vector<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicInitialAdmission {
    Admit { permit: u64 },
    Retry { token: Vector<u8> },
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicEndpointPacketDisposition {
    New,
    Duplicate,
    TooOld,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointConnectionPhase {
    Handshake,
    Established,
}

struct ConnectionIdEntry {
    id: Vector<u8>,
    connection: QuicConnectionHandle,
}

struct EndpointConnection {
    handle: QuicConnectionHandle,
    phase: EndpointConnectionPhase,
    validated_peer: SocketAddress,
    initial_packets: PacketReceiveState,
    handshake_packets: PacketReceiveState,
    application_packets: PacketReceiveState,
}

struct RetiredConnectionId {
    id: Vector<u8>,
    expires_at: u64,
}

/// Persistent UDP owner and bounded pre-decryption DCID router.
///
/// This layer deliberately does not interpret an unauthenticated source-address
/// change as migration. It labels it as a candidate for the connection's
/// existing authenticated PATH_CHALLENGE/PATH_RESPONSE state machine.
pub struct QuicServerEndpoint {
    socket: Option<UdpSocket>,
    connections: Vector<EndpointConnection>,
    connection_ids: Vector<ConnectionIdEntry>,
    retired_ids: Vector<RetiredConnectionId>,
    maximum_connections: usize,
    maximum_retired_ids: usize,
    admission: Option<QuicAdmissionController>,
    retry_tokens: Option<QuicRetryTokenManager>,
}

impl QuicServerEndpoint {
    pub fn bind(
        ip: [u8; 4],
        port: u16,
        maximum_connections: usize,
        maximum_retired_ids: usize,
    ) -> Result<Self, QuicError> {
        let socket = UdpSocket::bind(ip, port).map_err(|_| QuicError::SocketBind)?;
        Self::from_socket(socket, maximum_connections, maximum_retired_ids)
    }

    pub fn from_socket(
        socket: UdpSocket,
        maximum_connections: usize,
        maximum_retired_ids: usize,
    ) -> Result<Self, QuicError> {
        if maximum_connections == 0
            || maximum_connections > 65_536
            || maximum_retired_ids == 0
            || maximum_retired_ids > 65_536
        {
            return Err(QuicError::Limit);
        }
        Ok(Self {
            socket: Some(socket),
            connections: Vector::new(),
            connection_ids: Vector::new(),
            retired_ids: Vector::new(),
            maximum_connections,
            maximum_retired_ids,
            admission: None,
            retry_tokens: None,
        })
    }

    pub fn configure_public_admission(
        &mut self,
        admission: QuicAdmissionController,
        retry_tokens: QuicRetryTokenManager,
    ) {
        self.admission = Some(admission);
        self.retry_tokens = Some(retry_tokens);
    }

    pub fn admit_initial(
        &mut self,
        input: &[u8],
        peer: SocketAddress,
        now: u64,
        estimated_memory_bytes: u64,
    ) -> QuicInitialAdmission {
        if input.len() < 1200 {
            return QuicInitialAdmission::Reject;
        }
        let Ok((_, original_destination_id)) = initial_version_and_destination_id(input) else {
            return QuicInitialAdmission::Reject;
        };
        let Ok(token) = initial_token(input) else {
            return QuicInitialAdmission::Reject;
        };
        let (Some(admission), Some(tokens)) = (&mut self.admission, &mut self.retry_tokens) else {
            return QuicInitialAdmission::Reject;
        };
        let validated = if token.is_empty() {
            false
        } else if tokens
            .verify_and_consume(
                token,
                peer,
                &original_destination_id,
                now,
                QuicRetryPurpose::AddressValidation,
            )
            .is_ok()
        {
            true
        } else {
            return QuicInitialAdmission::Reject;
        };
        match admission.begin(peer, now, estimated_memory_bytes, validated) {
            QuicAdmissionDecision::Admit { permit } => QuicInitialAdmission::Admit { permit },
            QuicAdmissionDecision::Retry => match tokens.issue(
                peer,
                &original_destination_id,
                now,
                QuicRetryPurpose::AddressValidation,
            ) {
                Ok(token) => QuicInitialAdmission::Retry { token },
                Err(_) => QuicInitialAdmission::Reject,
            },
            QuicAdmissionDecision::Reject => QuicInitialAdmission::Reject,
        }
    }

    pub fn release_handshake_permit(&mut self, permit: u64) -> Result<(), QuicError> {
        self.admission
            .as_mut()
            .ok_or(QuicError::ProtocolViolation)?
            .release(permit)
    }

    pub fn local_port(&self) -> Result<u16, QuicError> {
        self.socket
            .as_ref()
            .ok_or(QuicError::SocketBind)?
            .local_port()
            .map_err(|_| QuicError::SocketBind)
    }

    pub fn register_handshake(
        &mut self,
        id: &[u8],
        connection: QuicConnectionHandle,
        validated_peer: SocketAddress,
    ) -> Result<(), QuicError> {
        self.register(
            id,
            connection,
            validated_peer,
            EndpointConnectionPhase::Handshake,
        )
    }

    pub fn mark_established(&mut self, connection: QuicConnectionHandle) -> Result<(), QuicError> {
        let entry = self
            .connections
            .iter_mut()
            .find(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        entry.phase = EndpointConnectionPhase::Established;
        Ok(())
    }

    pub fn register_connection_id(
        &mut self,
        id: &[u8],
        connection: QuicConnectionHandle,
        validated_peer: SocketAddress,
    ) -> Result<(), QuicError> {
        self.register(
            id,
            connection,
            validated_peer,
            EndpointConnectionPhase::Established,
        )
    }

    fn register(
        &mut self,
        id: &[u8],
        connection: QuicConnectionHandle,
        validated_peer: SocketAddress,
        phase: EndpointConnectionPhase,
    ) -> Result<(), QuicError> {
        if id.is_empty() || id.len() > MAX_CONNECTION_ID {
            return Err(QuicError::Limit);
        }
        if self
            .connection_ids
            .iter()
            .any(|entry| entry.id == id || entry.id.starts_with(id) || id.starts_with(&entry.id))
            || self.retired_ids.iter().any(|entry| entry.id == id)
        {
            return Err(QuicError::ConnectionId);
        }
        let mut owned = Vector::new();
        owned
            .try_extend_from_slice(id)
            .map_err(|_| QuicError::Allocation)?;
        let connection_index = self
            .connections
            .iter()
            .position(|entry| entry.handle == connection);
        if let Some(index) = connection_index {
            let entry = &self.connections[index];
            if entry.validated_peer != validated_peer || entry.phase != phase {
                return Err(QuicError::ProtocolViolation);
            }
            if self
                .connection_ids
                .iter()
                .filter(|entry| entry.connection == connection)
                .count()
                >= MAX_IDS_PER_CONNECTION
            {
                return Err(QuicError::Limit);
            }
        } else {
            if self.connections.len() >= self.maximum_connections {
                return Err(QuicError::Limit);
            }
            self.connections
                .try_push(EndpointConnection {
                    handle: connection,
                    phase,
                    validated_peer,
                    initial_packets: PacketReceiveState::new(),
                    handshake_packets: PacketReceiveState::new(),
                    application_packets: PacketReceiveState::new(),
                })
                .map_err(|_| QuicError::Allocation)?;
        }
        if self
            .connection_ids
            .try_push(ConnectionIdEntry {
                id: owned,
                connection,
            })
            .is_err()
        {
            if connection_index.is_none() {
                self.connections.pop();
            }
            return Err(QuicError::Allocation);
        }
        Ok(())
    }

    /// Records a packet only after header protection and AEAD authentication.
    /// Each connection owns independent bounded histories for all three QUIC
    /// packet-number spaces, so replay in one space cannot perturb another.
    pub fn record_authenticated_packet(
        &mut self,
        connection: QuicConnectionHandle,
        space: crate::QuicPacketSpace,
        packet_number: u64,
    ) -> Result<QuicEndpointPacketDisposition, QuicError> {
        let entry = self
            .connections
            .iter_mut()
            .find(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        let history = match space {
            crate::QuicPacketSpace::Initial => &mut entry.initial_packets,
            crate::QuicPacketSpace::Handshake => &mut entry.handshake_packets,
            crate::QuicPacketSpace::Application => &mut entry.application_packets,
        };
        Ok(match history.record(packet_number)? {
            ReceivedPacket::New => QuicEndpointPacketDisposition::New,
            ReceivedPacket::Duplicate => QuicEndpointPacketDisposition::Duplicate,
            ReceivedPacket::TooOld => QuicEndpointPacketDisposition::TooOld,
        })
    }

    pub fn update_validated_peer(
        &mut self,
        connection: QuicConnectionHandle,
        peer: SocketAddress,
    ) -> Result<(), QuicError> {
        let entry = self
            .connections
            .iter_mut()
            .find(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        entry.validated_peer = peer;
        Ok(())
    }

    pub fn remove_connection(&mut self, connection: QuicConnectionHandle) -> Result<(), QuicError> {
        let index = self
            .connections
            .iter()
            .position(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        self.connections.remove(index);
        let mut id_index = 0;
        while id_index < self.connection_ids.len() {
            if self.connection_ids[id_index].connection == connection {
                self.connection_ids.remove(id_index);
            } else {
                id_index += 1;
            }
        }
        Ok(())
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn retire_connection_id(&mut self, id: &[u8], expires_at: u64) -> Result<(), QuicError> {
        let index = self
            .connection_ids
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(QuicError::ConnectionId)?;
        if self.retired_ids.len() >= self.maximum_retired_ids {
            return Err(QuicError::Limit);
        }
        let entry = self.connection_ids.remove(index);
        self.retired_ids
            .try_push(RetiredConnectionId {
                id: entry.id,
                expires_at,
            })
            .map_err(|_| QuicError::Allocation)
    }

    pub fn reap_retired(&mut self, now: u64) {
        let mut index = 0;
        while index < self.retired_ids.len() {
            if self.retired_ids[index].expires_at < now {
                self.retired_ids.remove(index);
            } else {
                index += 1;
            }
        }
    }

    pub fn receive(&mut self) -> Result<QuicEndpointDatagram, QuicError> {
        let mut datagram = [0; MAX_DATAGRAM];
        loop {
            let (amount, peer) = self
                .socket
                .as_ref()
                .ok_or(QuicError::SocketRead)?
                .receive_from(&mut datagram)
                .map_err(|_| QuicError::SocketRead)?;
            if let Some(datagram) = self.dispatch_datagram(peer, &datagram[..amount])? {
                return Ok(datagram);
            }
        }
    }

    /// Classifies one received datagram for the persistent endpoint reactor.
    /// Noise is returned as `None`; it cannot terminate the listener or mutate
    /// another connection. Bytes are copied only after bounded DCID routing has
    /// selected a connection or a syntactically valid new Initial.
    pub fn dispatch_datagram(
        &self,
        peer: SocketAddress,
        input: &[u8],
    ) -> Result<Option<QuicEndpointDatagram>, QuicError> {
        if input.len() > MAX_DATAGRAM {
            return Ok(None);
        }
        let Some(route) = self.route(input, peer) else {
            return Ok(None);
        };
        let mut bytes = Vector::new();
        bytes
            .try_extend_from_slice(input)
            .map_err(|_| QuicError::Allocation)?;
        Ok(Some(QuicEndpointDatagram { peer, route, bytes }))
    }

    fn route(&self, input: &[u8], peer: SocketAddress) -> Option<QuicEndpointRoute> {
        if input.first().is_some_and(|first| first & 0xc0 == 0x40) {
            if self
                .retired_ids
                .iter()
                .any(|entry| input[1..].starts_with(&entry.id))
            {
                return None;
            }
            let entry = self
                .connection_ids
                .iter()
                .find(|entry| input[1..].starts_with(&entry.id))?;
            return self.route_entry(entry, peer);
        }
        let destination = destination_connection_id(input)?;
        if self.retired_ids.iter().any(|entry| entry.id == destination) {
            return None;
        }
        if let Some(entry) = self
            .connection_ids
            .iter()
            .find(|entry| entry.id == destination)
        {
            return self.route_entry(entry, peer);
        }
        if input.len() < 1200 {
            return None;
        }
        let (version, original_destination_id) = initial_version_and_destination_id(input).ok()?;
        Some(QuicEndpointRoute::NewInitial {
            version,
            original_destination_id,
        })
    }

    fn route_entry(
        &self,
        entry: &ConnectionIdEntry,
        peer: SocketAddress,
    ) -> Option<QuicEndpointRoute> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.handle == entry.connection)?;
        Some(match connection.phase {
            EndpointConnectionPhase::Handshake => {
                if peer != connection.validated_peer {
                    return None;
                }
                QuicEndpointRoute::Handshake(entry.connection)
            }
            EndpointConnectionPhase::Established => QuicEndpointRoute::Established {
                connection: entry.connection,
                path: if peer == connection.validated_peer {
                    QuicPathClassification::Validated
                } else {
                    QuicPathClassification::Candidate
                },
            },
        })
    }
}

fn destination_connection_id(input: &[u8]) -> Option<&[u8]> {
    if input.is_empty() || input[0] & 0x40 == 0 {
        return None;
    }
    if input[0] & 0x80 != 0 {
        let length = *input.get(5)? as usize;
        if length > MAX_CONNECTION_ID || input.len().saturating_sub(6) < length {
            return None;
        }
        Some(&input[6..6 + length])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InitialPacket, QuicInitialKeys, QuicRetryKey, QuicRole};

    fn peer(port: u16) -> SocketAddress {
        SocketAddress {
            ip: [192, 0, 2, 1],
            port,
        }
    }

    fn endpoint(maximum_connections: usize, maximum_retired_ids: usize) -> QuicServerEndpoint {
        QuicServerEndpoint {
            socket: None,
            connections: Vector::new(),
            connection_ids: Vector::new(),
            retired_ids: Vector::new(),
            maximum_connections,
            maximum_retired_ids,
            admission: None,
            retry_tokens: None,
        }
    }

    #[test]
    fn long_header_routes_before_decryption_and_preserves_validated_peer() {
        let mut endpoint = endpoint(2, 2);
        endpoint
            .register_handshake(&[1, 2, 3, 4], QuicConnectionHandle(7), peer(443))
            .unwrap();
        let mut packet = Vector::new();
        packet
            .try_extend_from_slice(&[0xd0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0])
            .unwrap();
        assert_eq!(
            endpoint.route(&packet, peer(443)),
            Some(QuicEndpointRoute::Handshake(QuicConnectionHandle(7)))
        );
        endpoint.mark_established(QuicConnectionHandle(7)).unwrap();
        assert_eq!(
            endpoint.route(&packet, peer(444)),
            Some(QuicEndpointRoute::Established {
                connection: QuicConnectionHandle(7),
                path: QuicPathClassification::Candidate
            })
        );
        assert_eq!(
            endpoint.route(&packet, peer(443)),
            Some(QuicEndpointRoute::Established {
                connection: QuicConnectionHandle(7),
                path: QuicPathClassification::Validated
            })
        );
        let short = [0x40, 1, 2, 3, 4, 0xaa];
        assert_eq!(
            endpoint.route(&short, peer(443)),
            Some(QuicEndpointRoute::Established {
                connection: QuicConnectionHandle(7),
                path: QuicPathClassification::Validated
            })
        );
    }

    #[test]
    fn malformed_unknown_and_retired_ids_are_connection_local_noise() {
        let mut endpoint = endpoint(1, 1);
        assert_eq!(endpoint.route(&[0xd0], peer(1)), None);
        endpoint
            .register_connection_id(&[9], QuicConnectionHandle(1), peer(1))
            .unwrap();
        endpoint.retire_connection_id(&[9], 10).unwrap();
        let packet = [0xd0, 0, 0, 0, 1, 1, 9];
        assert_eq!(endpoint.route(&packet, peer(1)), None);
        endpoint.reap_retired(11);
        assert!(endpoint.retired_ids.is_empty());
    }

    #[test]
    fn endpoint_authenticates_retry_before_allocating_a_handshake_permit() {
        let mut endpoint = endpoint(2, 2);
        endpoint.configure_public_admission(
            QuicAdmissionController::new(2, 1, 4096, 30, 0).unwrap(),
            QuicRetryTokenManager::new(
                QuicRetryKey {
                    generation: 1,
                    key: [7; 16],
                },
                30,
            )
            .unwrap(),
        );
        let initial = InitialPacket {
            destination_id: [1, 2, 3, 4].into(),
            source_id: [5, 6, 7, 8].into(),
            packet_number: 0,
            payload: [0; 1150].into(),
        };
        let keys =
            QuicInitialKeys::derive_for(QuicVersion::V2, &initial.destination_id, QuicRole::Client)
                .unwrap();
        let first = initial.seal_padded_for(QuicVersion::V2, &keys).unwrap();
        let QuicInitialAdmission::Retry { token } =
            endpoint.admit_initial(&first, peer(443), 100, 1024)
        else {
            panic!("unvalidated Initial did not receive Retry")
        };
        let retried = initial
            .seal_for_with_token(QuicVersion::V2, &keys, &token)
            .unwrap();
        assert_eq!(
            endpoint.admit_initial(&retried, peer(444), 101, 1024),
            QuicInitialAdmission::Reject
        );
        assert_eq!(
            endpoint.admit_initial(&retried, peer(443), 101, 1024),
            QuicInitialAdmission::Admit { permit: 1 }
        );
        assert_eq!(
            endpoint.admit_initial(&retried, peer(443), 101, 1024),
            QuicInitialAdmission::Reject
        );
        endpoint.release_handshake_permit(1).unwrap();
    }

    #[test]
    fn endpoint_owns_bounded_connection_lifecycle_and_packet_spaces() {
        let mut endpoint = endpoint(1, 8);
        let connection = QuicConnectionHandle(7);
        endpoint
            .register_handshake(&[1, 2, 3, 4], connection, peer(443))
            .unwrap();
        assert_eq!(endpoint.connection_count(), 1);
        assert_eq!(
            endpoint.record_authenticated_packet(connection, crate::QuicPacketSpace::Initial, 9),
            Ok(QuicEndpointPacketDisposition::New)
        );
        assert_eq!(
            endpoint.record_authenticated_packet(connection, crate::QuicPacketSpace::Initial, 9),
            Ok(QuicEndpointPacketDisposition::Duplicate)
        );
        assert_eq!(
            endpoint.record_authenticated_packet(connection, crate::QuicPacketSpace::Handshake, 9),
            Ok(QuicEndpointPacketDisposition::New)
        );
        assert_eq!(
            endpoint.record_authenticated_packet(
                connection,
                crate::QuicPacketSpace::Application,
                9
            ),
            Ok(QuicEndpointPacketDisposition::New)
        );

        assert_eq!(
            endpoint.register_handshake(&[5, 6, 7, 8], QuicConnectionHandle(8), peer(444)),
            Err(QuicError::Limit)
        );
        endpoint.mark_established(connection).unwrap();
        endpoint
            .update_validated_peer(connection, peer(444))
            .unwrap();
        let packet = [0x40, 1, 2, 3, 4, 0xaa];
        assert_eq!(
            endpoint.route(&packet, peer(444)),
            Some(QuicEndpointRoute::Established {
                connection,
                path: QuicPathClassification::Validated
            })
        );
        endpoint.remove_connection(connection).unwrap();
        assert_eq!(endpoint.connection_count(), 0);
        assert_eq!(endpoint.route(&packet, peer(444)), None);
    }

    #[test]
    fn persistent_dispatch_isolates_junk_and_interleaved_connections() {
        let mut endpoint = endpoint(2, 4);
        let first = QuicConnectionHandle(11);
        let second = QuicConnectionHandle(12);
        endpoint
            .register_handshake(&[1, 1, 1, 1], first, peer(443))
            .unwrap();
        endpoint
            .register_handshake(&[2, 2, 2, 2], second, peer(444))
            .unwrap();

        for junk in [
            &[][..],
            &[0xd0][..],
            &[0x40, 9, 9, 9, 9, 0xaa][..],
            &[0x00, 1, 2, 3][..],
        ] {
            assert_eq!(endpoint.dispatch_datagram(peer(999), junk), Ok(None));
        }
        let first_packet = [0x40, 1, 1, 1, 1, 0xaa];
        let second_packet = [0x40, 2, 2, 2, 2, 0xbb];
        assert_eq!(
            endpoint.dispatch_datagram(peer(999), &first_packet),
            Ok(None),
            "an unrelated peer cannot enter an in-progress handshake"
        );
        assert_eq!(
            endpoint
                .dispatch_datagram(peer(443), &first_packet)
                .unwrap()
                .map(|datagram| datagram.route),
            Some(QuicEndpointRoute::Handshake(first))
        );
        assert_eq!(
            endpoint
                .dispatch_datagram(peer(444), &second_packet)
                .unwrap()
                .map(|datagram| datagram.route),
            Some(QuicEndpointRoute::Handshake(second))
        );

        endpoint.mark_established(first).unwrap();
        endpoint.mark_established(second).unwrap();
        assert_eq!(
            endpoint
                .dispatch_datagram(peer(443), &first_packet)
                .unwrap()
                .map(|datagram| datagram.route),
            Some(QuicEndpointRoute::Established {
                connection: first,
                path: QuicPathClassification::Validated,
            })
        );
        assert_eq!(
            endpoint
                .dispatch_datagram(peer(444), &second_packet)
                .unwrap()
                .map(|datagram| datagram.route),
            Some(QuicEndpointRoute::Established {
                connection: second,
                path: QuicPathClassification::Validated,
            })
        );
        assert_eq!(endpoint.connection_count(), 2);
    }
}
