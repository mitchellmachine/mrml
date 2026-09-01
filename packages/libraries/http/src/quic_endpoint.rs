use mrml_runtime::{SocketAddress, UdpSocket, Vector};

use crate::quic::initial_version_and_destination_id;
use crate::{QuicError, QuicVersion};

const MAX_DATAGRAM: usize = 65_527;
const MAX_CONNECTION_ID: usize = 20;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointConnectionPhase {
    Handshake,
    Established,
}

struct ConnectionIdEntry {
    id: Vector<u8>,
    connection: QuicConnectionHandle,
    phase: EndpointConnectionPhase,
    validated_peer: SocketAddress,
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
    connection_ids: Vector<ConnectionIdEntry>,
    retired_ids: Vector<RetiredConnectionId>,
    maximum_connections: usize,
    maximum_retired_ids: usize,
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
            connection_ids: Vector::new(),
            retired_ids: Vector::new(),
            maximum_connections,
            maximum_retired_ids,
        })
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
        let mut found = false;
        for entry in &mut self.connection_ids {
            if entry.connection == connection {
                entry.phase = EndpointConnectionPhase::Established;
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(QuicError::ConnectionId)
        }
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
        if id.is_empty()
            || id.len() > MAX_CONNECTION_ID
            || self.connection_ids.len() >= self.maximum_connections
        {
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
        self.connection_ids
            .try_push(ConnectionIdEntry {
                id: owned,
                connection,
                phase,
                validated_peer,
            })
            .map_err(|_| QuicError::Allocation)
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
            let Some(route) = self.route(&datagram[..amount], peer) else {
                continue;
            };
            let mut bytes = Vector::new();
            bytes
                .try_extend_from_slice(&datagram[..amount])
                .map_err(|_| QuicError::Allocation)?;
            return Ok(QuicEndpointDatagram { peer, route, bytes });
        }
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
            return Some(self.route_entry(entry, peer));
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
            return Some(self.route_entry(entry, peer));
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

    fn route_entry(&self, entry: &ConnectionIdEntry, peer: SocketAddress) -> QuicEndpointRoute {
        match entry.phase {
            EndpointConnectionPhase::Handshake => QuicEndpointRoute::Handshake(entry.connection),
            EndpointConnectionPhase::Established => QuicEndpointRoute::Established {
                connection: entry.connection,
                path: if peer == entry.validated_peer {
                    QuicPathClassification::Validated
                } else {
                    QuicPathClassification::Candidate
                },
            },
        }
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

    fn peer(port: u16) -> SocketAddress {
        SocketAddress {
            ip: [192, 0, 2, 1],
            port,
        }
    }

    fn endpoint(maximum_connections: usize, maximum_retired_ids: usize) -> QuicServerEndpoint {
        QuicServerEndpoint {
            socket: None,
            connection_ids: Vector::new(),
            retired_ids: Vector::new(),
            maximum_connections,
            maximum_retired_ids,
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
}
