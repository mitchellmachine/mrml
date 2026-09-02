use mrml_runtime::{
    Sender, Shared, SocketAddress, TrySendError, UdpSocket, Vector, blocking_channel,
};

use crate::quic::{
    PacketReceiveState, ReceivedPacket, initial_source_id, initial_token,
    initial_version_and_destination_id,
};
use crate::quic_retry::{
    QuicAdmissionController, QuicAdmissionDecision, QuicRetryPurpose, QuicRetryTokenManager,
};
use crate::quic_connection::QuicRoutedDatagram;
use crate::{
    GitdResourceController, GitdWorkClass, QuicError, QuicVersion, RetryPacket, SourceIdentity,
};
use crate::QuicServerListener;

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

pub struct QuicAdmittedHandshake {
    pub connection: QuicConnectionHandle,
    pub permit: u64,
    pub listener: QuicServerListener,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicEndpointMetrics {
    pub datagrams_received: u64,
    pub bytes_received: u64,
    pub datagrams_dropped: u64,
    pub new_initials: u64,
    pub handshake_datagrams: u64,
    pub established_datagrams: u64,
    pub candidate_path_datagrams: u64,
    pub retry_datagrams_sent: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicInitialAdmission {
    Admit {
        permit: u64,
        original_destination_id: Vector<u8>,
    },
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
    resource_connection_admitted: bool,
    inbound: Option<Sender<QuicRoutedDatagram>>,
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
    socket: Option<Shared<UdpSocket>>,
    connections: Vector<EndpointConnection>,
    connection_ids: Vector<ConnectionIdEntry>,
    retired_ids: Vector<RetiredConnectionId>,
    maximum_connections: usize,
    maximum_retired_ids: usize,
    admission: Option<QuicAdmissionController>,
    retry_tokens: Option<QuicRetryTokenManager>,
    resources: Option<GitdResourceController>,
    resource_handshake_permits: Vector<u64>,
    metrics: QuicEndpointMetrics,
    next_connection_handle: u64,
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
            socket: Some(Shared::new(socket)),
            connections: Vector::new(),
            connection_ids: Vector::new(),
            retired_ids: Vector::new(),
            maximum_connections,
            maximum_retired_ids,
            admission: None,
            retry_tokens: None,
            resources: None,
            resource_handshake_permits: Vector::new(),
            metrics: QuicEndpointMetrics::default(),
            next_connection_handle: 1,
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

    pub fn configure_resource_controller(&mut self, resources: GitdResourceController) {
        self.resources = Some(resources);
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
        let authenticated_original_destination_id = if token.is_empty() {
            None
        } else {
            match tokens.verify_retry_and_consume(token, peer, now) {
                Ok(original_destination_id) => Some(original_destination_id),
                Err(_) => return QuicInitialAdmission::Reject,
            }
        };
        let validated = authenticated_original_destination_id.is_some();
        match admission.begin(peer, now, estimated_memory_bytes, validated) {
            QuicAdmissionDecision::Admit { permit } => {
                if let Some(resources) = &mut self.resources {
                    if !resources.admit(
                        SourceIdentity::ipv4(peer.ip),
                        GitdWorkClass::Handshake,
                        now,
                    ) {
                        let _ = admission.release(permit);
                        return QuicInitialAdmission::Reject;
                    }
                    if self.resource_handshake_permits.try_push(permit).is_err() {
                        resources.complete(GitdWorkClass::Handshake);
                        let _ = admission.release(permit);
                        return QuicInitialAdmission::Reject;
                    }
                }
                let Some(original_destination_id) = authenticated_original_destination_id else {
                    let _ = admission.release(permit);
                    if let Some(resources) = &mut self.resources {
                        if let Some(index) = self
                            .resource_handshake_permits
                            .iter()
                            .position(|candidate| *candidate == permit)
                        {
                            self.resource_handshake_permits.remove(index);
                            resources.complete(GitdWorkClass::Handshake);
                        }
                    }
                    return QuicInitialAdmission::Reject;
                };
                QuicInitialAdmission::Admit {
                    permit,
                    original_destination_id,
                }
            }
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
        let resource_index = if self.resources.is_some() {
            Some(
                self.resource_handshake_permits
                    .iter()
                    .position(|candidate| *candidate == permit)
                    .ok_or(QuicError::ProtocolViolation)?,
            )
        } else {
            None
        };
        self.admission
            .as_mut()
            .ok_or(QuicError::ProtocolViolation)?
            .release(permit)?;
        if let (Some(resources), Some(index)) = (&mut self.resources, resource_index) {
            self.resource_handshake_permits.remove(index);
            resources.complete(GitdWorkClass::Handshake);
        }
        Ok(())
    }

    pub fn send_retry(
        &mut self,
        datagram: &QuicEndpointDatagram,
        token: &[u8],
    ) -> Result<(), QuicError> {
        let QuicEndpointRoute::NewInitial {
            version,
            original_destination_id,
        } = &datagram.route
        else {
            return Err(QuicError::ProtocolViolation);
        };
        let destination_id = initial_source_id(&datagram.bytes)?;
        if destination_id.is_empty() {
            return Err(QuicError::ConnectionId);
        }
        let mut source_id = [0; 16];
        mrml_runtime::fill_random(&mut source_id).map_err(|_| QuicError::Crypto)?;
        let retry = RetryPacket {
            destination_id,
            source_id: source_id.into(),
            token: {
                let mut owned = Vector::new();
                owned
                    .try_extend_from_slice(token)
                    .map_err(|_| QuicError::Allocation)?;
                owned
            },
        }
        .seal(*version, original_destination_id)?;
        let socket = self.socket.as_ref().ok_or(QuicError::SocketWrite)?;
        if socket
            .send_to(&retry, datagram.peer)
            .map_err(|_| QuicError::SocketWrite)?
            != retry.len()
        {
            return Err(QuicError::SocketWrite);
        }
        self.metrics.retry_datagrams_sent = self.metrics.retry_datagrams_sent.saturating_add(1);
        Ok(())
    }

    /// Applies admission and constructs a routed handshake as one fail-closed
    /// endpoint transaction. Retry and rejection intentionally return `None`.
    pub fn admit_endpoint_datagram(
        &mut self,
        datagram: QuicEndpointDatagram,
        now: u64,
        estimated_memory_bytes: u64,
        queue_capacity: usize,
    ) -> Result<Option<QuicAdmittedHandshake>, QuicError> {
        match self.admit_initial(
            &datagram.bytes,
            datagram.peer,
            now,
            estimated_memory_bytes,
        ) {
            QuicInitialAdmission::Retry { token } => {
                self.send_retry(&datagram, &token)?;
                Ok(None)
            }
            QuicInitialAdmission::Reject => Ok(None),
            QuicInitialAdmission::Admit {
                permit,
                original_destination_id,
            } => {
                let connection = match self.allocate_connection_handle() {
                    Ok(connection) => connection,
                    Err(error) => {
                        let _ = self.release_handshake_permit(permit);
                        return Err(error);
                    }
                };
                match self.begin_routed_handshake(
                    datagram,
                    original_destination_id,
                    connection,
                    queue_capacity,
                ) {
                    Ok(listener) => Ok(Some(QuicAdmittedHandshake {
                        connection,
                        permit,
                        listener,
                    })),
                    Err(error) => {
                        let _ = self.release_handshake_permit(permit);
                        Err(error)
                    }
                }
            }
        }
    }

    fn allocate_connection_handle(&mut self) -> Result<QuicConnectionHandle, QuicError> {
        for _ in 0..=self.maximum_connections {
            let value = self.next_connection_handle;
            self.next_connection_handle = self
                .next_connection_handle
                .checked_add(1)
                .filter(|next| *next != 0)
                .unwrap_or(1);
            let handle = QuicConnectionHandle(value);
            if !self.connections.iter().any(|entry| entry.handle == handle) {
                return Ok(handle);
            }
        }
        Err(QuicError::Limit)
    }

    /// Reconciles admission timeouts with resource permits. The endpoint owns
    /// both ledgers so an abandoned handshake cannot permanently consume a
    /// reactor work slot.
    pub fn reap_handshakes(&mut self, now: u64) {
        let Some(admission) = &mut self.admission else {
            return;
        };
        admission.reap(now);
        let Some(resources) = &mut self.resources else {
            return;
        };
        let mut index = 0;
        while index < self.resource_handshake_permits.len() {
            if admission.contains_permit(self.resource_handshake_permits[index]) {
                index += 1;
            } else {
                self.resource_handshake_permits.remove(index);
                resources.complete(GitdWorkClass::Handshake);
            }
        }
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
        self.mark_established_at(connection, 0)
    }

    pub fn mark_established_at(
        &mut self,
        connection: QuicConnectionHandle,
        now: u64,
    ) -> Result<(), QuicError> {
        let index = self
            .connections
            .iter()
            .position(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        if self.connections[index].phase == EndpointConnectionPhase::Established {
            return Ok(());
        }
        if let Some(resources) = &mut self.resources {
            if !resources.admit(
                SourceIdentity::ipv4(self.connections[index].validated_peer.ip),
                GitdWorkClass::OpenConnection,
                now,
            ) {
                return Err(QuicError::FlowControl);
            }
            self.connections[index].resource_connection_admitted = true;
        }
        self.connections[index].phase = EndpointConnectionPhase::Established;
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
            if phase == EndpointConnectionPhase::Established && self.resources.is_some() {
                return Err(QuicError::ProtocolViolation);
            }
            self.connections
                .try_push(EndpointConnection {
                    handle: connection,
                    phase,
                    validated_peer,
                    initial_packets: PacketReceiveState::new(),
                    handshake_packets: PacketReceiveState::new(),
                    application_packets: PacketReceiveState::new(),
                    resource_connection_admitted: false,
                    inbound: None,
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
        if self.connections[index].resource_connection_admitted
            && let Some(resources) = &mut self.resources
        {
            resources.complete(GitdWorkClass::OpenConnection);
        }
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

    pub fn metrics(&self) -> QuicEndpointMetrics {
        self.metrics
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

    /// Returns the next syntactically valid Initial while routing datagrams for
    /// known connections into their bounded queues. A saturated connection is
    /// treated as connection-local packet loss and cannot stall the endpoint.
    pub fn receive_new_initial(&mut self) -> Result<QuicEndpointDatagram, QuicError> {
        loop {
            let datagram = self.receive()?;
            if matches!(datagram.route, QuicEndpointRoute::NewInitial { .. }) {
                return Ok(datagram);
            }
            match self.route_routed_datagram(datagram) {
                Ok(()) | Err(QuicError::FlowControl | QuicError::ConnectionId) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Creates one bounded connection-local receive queue and transfers the
    /// admitted Initial into it. The endpoint remains the only UDP reader.
    pub fn begin_routed_handshake(
        &mut self,
        datagram: QuicEndpointDatagram,
        original_destination_id: Vector<u8>,
        connection: QuicConnectionHandle,
        queue_capacity: usize,
    ) -> Result<QuicServerListener, QuicError> {
        if queue_capacity == 0 || queue_capacity > 256 {
            return Err(QuicError::Limit);
        }
        let QuicEndpointRoute::NewInitial {
            original_destination_id: received_destination_id,
            ..
        } = &datagram.route
        else {
            return Err(QuicError::ProtocolViolation);
        };
        let socket = self.socket.as_ref().ok_or(QuicError::SocketBind)?.clone();
        let (inbound, receiver) = blocking_channel(queue_capacity);
        let (listener, server_connection_id) = QuicServerListener::from_routed_datagrams(
            socket,
            receiver,
            original_destination_id,
        )?;
        self.register_handshake(received_destination_id, connection, datagram.peer)?;
        if let Err(error) =
            self.register_handshake(&server_connection_id, connection, datagram.peer)
        {
            let _ = self.remove_connection(connection);
            return Err(error);
        }
        let entry = self
            .connections
            .iter_mut()
            .find(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        entry.inbound = Some(inbound.clone());
        let routed = QuicRoutedDatagram {
            peer: datagram.peer,
            bytes: datagram.bytes,
        };
        if inbound.try_send(routed).is_err() {
            let _ = self.remove_connection(connection);
            return Err(QuicError::FlowControl);
        }
        Ok(listener)
    }

    pub fn route_routed_datagram(
        &mut self,
        datagram: QuicEndpointDatagram,
    ) -> Result<(), QuicError> {
        let connection = match datagram.route {
            QuicEndpointRoute::Handshake(connection)
            | QuicEndpointRoute::Established { connection, .. } => connection,
            QuicEndpointRoute::NewInitial { .. } => {
                return Err(QuicError::ProtocolViolation);
            }
        };
        let entry = self
            .connections
            .iter()
            .find(|entry| entry.handle == connection)
            .ok_or(QuicError::ConnectionId)?;
        let inbound = entry.inbound.as_ref().ok_or(QuicError::ConnectionId)?;
        let routed = QuicRoutedDatagram {
            peer: datagram.peer,
            bytes: datagram.bytes,
        };
        match inbound.try_send(routed) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.metrics.datagrams_dropped = self.metrics.datagrams_dropped.saturating_add(1);
                Err(QuicError::FlowControl)
            }
            Err(TrySendError::Disconnected(_)) => {
                let _ = self.remove_connection(connection);
                Err(QuicError::ConnectionId)
            }
        }
    }

    /// Classifies one received datagram for the persistent endpoint reactor.
    /// Noise is returned as `None`; it cannot terminate the listener or mutate
    /// another connection. Bytes are copied only after bounded DCID routing has
    /// selected a connection or a syntactically valid new Initial.
    pub fn dispatch_datagram(
        &mut self,
        peer: SocketAddress,
        input: &[u8],
    ) -> Result<Option<QuicEndpointDatagram>, QuicError> {
        self.metrics.datagrams_received = self.metrics.datagrams_received.saturating_add(1);
        self.metrics.bytes_received = self
            .metrics
            .bytes_received
            .saturating_add(input.len() as u64);
        if input.len() > MAX_DATAGRAM {
            self.metrics.datagrams_dropped = self.metrics.datagrams_dropped.saturating_add(1);
            return Ok(None);
        }
        let Some(route) = self.route(input, peer) else {
            self.metrics.datagrams_dropped = self.metrics.datagrams_dropped.saturating_add(1);
            return Ok(None);
        };
        match &route {
            QuicEndpointRoute::NewInitial { .. } => {
                self.metrics.new_initials = self.metrics.new_initials.saturating_add(1)
            }
            QuicEndpointRoute::Handshake(_) => {
                self.metrics.handshake_datagrams =
                    self.metrics.handshake_datagrams.saturating_add(1)
            }
            QuicEndpointRoute::Established { path, .. } => {
                self.metrics.established_datagrams =
                    self.metrics.established_datagrams.saturating_add(1);
                if *path == QuicPathClassification::Candidate {
                    self.metrics.candidate_path_datagrams =
                        self.metrics.candidate_path_datagrams.saturating_add(1);
                }
            }
        }
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
            resources: None,
            resource_handshake_permits: Vector::new(),
            metrics: QuicEndpointMetrics::default(),
            next_connection_handle: 1,
        }
    }

    fn initial_datagram(destination_id: &[u8]) -> Vector<u8> {
        let mut owned_destination_id = Vector::new();
        owned_destination_id
            .try_extend_from_slice(destination_id)
            .unwrap();
        let initial = InitialPacket {
            destination_id: owned_destination_id,
            source_id: [5, 6, 7, 8].into(),
            packet_number: 0,
            payload: [0; 1150].into(),
        };
        let keys = QuicInitialKeys::derive_for(
            QuicVersion::V2,
            &initial.destination_id,
            QuicRole::Client,
        )
        .unwrap();
        initial.seal_padded_for(QuicVersion::V2, &keys).unwrap()
    }

    #[test]
    fn routed_handshake_queue_is_bounded_and_disconnect_retires_connection() {
        let socket = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        let mut endpoint = QuicServerEndpoint::from_socket(socket, 1, 4).unwrap();
        let connection = QuicConnectionHandle(41);
        let initial = initial_datagram(&[1, 2, 3, 4]);
        let datagram = endpoint
            .dispatch_datagram(peer(443), &initial)
            .unwrap()
            .unwrap();
        let listener = endpoint
            .begin_routed_handshake(datagram, [1, 2, 3, 4].into(), connection, 1)
            .unwrap();
        assert_eq!(endpoint.connection_count(), 1);

        let queued = endpoint
            .dispatch_datagram(peer(443), &initial)
            .unwrap()
            .unwrap();
        assert_eq!(
            endpoint.route_routed_datagram(queued),
            Err(QuicError::FlowControl)
        );
        assert_eq!(endpoint.metrics().datagrams_dropped, 1);

        drop(listener);
        let disconnected = endpoint
            .dispatch_datagram(peer(443), &initial)
            .unwrap()
            .unwrap();
        assert_eq!(
            endpoint.route_routed_datagram(disconnected),
            Err(QuicError::ConnectionId)
        );
        assert_eq!(endpoint.connection_count(), 0);
    }

    #[test]
    fn endpoint_sends_authenticated_retry_to_initial_source() {
        let server = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        let client = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        client.set_read_timeout_millis(1_000).unwrap();
        let client_peer = SocketAddress {
            ip: [127, 0, 0, 1],
            port: client.local_port().unwrap(),
        };
        let mut endpoint = QuicServerEndpoint::from_socket(server, 1, 4).unwrap();
        let initial = initial_datagram(&[1, 2, 3, 4]);
        let datagram = endpoint
            .dispatch_datagram(client_peer, &initial)
            .unwrap()
            .unwrap();
        endpoint.send_retry(&datagram, b"opaque-token").unwrap();

        let mut wire = [0; 512];
        let (amount, _) = client.receive_from(&mut wire).unwrap();
        let (version, retry) =
            RetryPacket::open(&wire[..amount], &[1, 2, 3, 4]).unwrap();
        assert_eq!(version, QuicVersion::V2);
        assert_eq!(retry.destination_id, &[5, 6, 7, 8][..]);
        assert_eq!(retry.token, b"opaque-token".as_slice());
        assert_eq!(endpoint.metrics().retry_datagrams_sent, 1);
    }

    #[test]
    fn endpoint_admission_atomically_retries_then_constructs_bounded_handshake() {
        let server = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        let client = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        client.set_read_timeout_millis(1_000).unwrap();
        let client_peer = SocketAddress {
            ip: [127, 0, 0, 1],
            port: client.local_port().unwrap(),
        };
        let mut endpoint = QuicServerEndpoint::from_socket(server, 2, 4).unwrap();
        endpoint.configure_public_admission(
            QuicAdmissionController::new(2, 2, 4096, 30, 0).unwrap(),
            QuicRetryTokenManager::new(
                QuicRetryKey {
                    generation: 1,
                    key: [7; 16],
                },
                30,
            )
            .unwrap(),
        );
        endpoint.configure_resource_controller(GitdResourceController::new(2).unwrap());

        let original_id = [1, 2, 3, 4];
        let initial = initial_datagram(&original_id);
        let datagram = endpoint
            .dispatch_datagram(client_peer, &initial)
            .unwrap()
            .unwrap();
        assert!(
            endpoint
                .admit_endpoint_datagram(datagram, 100, 1024, 4)
                .unwrap()
                .is_none()
        );
        let mut wire = [0; 512];
        let (amount, _) = client.receive_from(&mut wire).unwrap();
        let (_, retry) = RetryPacket::open(&wire[..amount], &original_id).unwrap();

        let retried = InitialPacket {
            destination_id: retry.source_id.clone(),
            source_id: [5, 6, 7, 8].into(),
            packet_number: 0,
            payload: [0; 1150].into(),
        };
        let keys = QuicInitialKeys::derive_for(
            QuicVersion::V2,
            &retried.destination_id,
            QuicRole::Client,
        )
        .unwrap();
        let retried = retried
            .seal_padded_for_with_token(QuicVersion::V2, &keys, &retry.token)
            .unwrap();
        let datagram = endpoint
            .dispatch_datagram(client_peer, &retried)
            .unwrap()
            .unwrap();
        let admitted = endpoint
            .admit_endpoint_datagram(datagram, 101, 1024, 4)
            .unwrap()
            .unwrap();
        assert_eq!(admitted.connection, QuicConnectionHandle(1));
        assert_eq!(admitted.permit, 1);
        assert_eq!(endpoint.connection_count(), 1);
        let connection = admitted.connection;
        let permit = admitted.permit;
        drop(admitted.listener);
        endpoint.remove_connection(connection).unwrap();
        endpoint.release_handshake_permit(permit).unwrap();
        assert_eq!(endpoint.connection_count(), 0);
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
        endpoint.configure_resource_controller(GitdResourceController::new(2).unwrap());
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
        let retried_initial = InitialPacket {
            destination_id: [9, 10, 11, 12].into(),
            source_id: initial.source_id.clone(),
            packet_number: 0,
            payload: initial.payload.clone(),
        };
        let retried_keys = QuicInitialKeys::derive_for(
            QuicVersion::V2,
            &retried_initial.destination_id,
            QuicRole::Client,
        )
        .unwrap();
        let retried = retried_initial
            .seal_for_with_token(QuicVersion::V2, &retried_keys, &token)
            .unwrap();
        assert_eq!(
            endpoint.admit_initial(&retried, peer(444), 101, 1024),
            QuicInitialAdmission::Reject
        );
        assert_eq!(
            endpoint.admit_initial(&retried, peer(443), 101, 1024),
            QuicInitialAdmission::Admit {
                permit: 1,
                original_destination_id: [1, 2, 3, 4].into(),
            }
        );
        assert_eq!(
            endpoint
                .resources
                .as_ref()
                .unwrap()
                .active_count(GitdWorkClass::Handshake),
            1
        );
        assert_eq!(
            endpoint.admit_initial(&retried, peer(443), 101, 1024),
            QuicInitialAdmission::Reject
        );
        endpoint.release_handshake_permit(1).unwrap();
        assert_eq!(
            endpoint
                .resources
                .as_ref()
                .unwrap()
                .active_count(GitdWorkClass::Handshake),
            0
        );
        let token = endpoint
            .retry_tokens
            .as_ref()
            .unwrap()
            .issue(
                peer(443),
                &initial.destination_id,
                102,
                QuicRetryPurpose::AddressValidation,
            )
            .unwrap();
        let retried = initial
            .seal_for_with_token(QuicVersion::V2, &keys, &token)
            .unwrap();
        assert_eq!(
            endpoint.admit_initial(&retried, peer(443), 102, 1024),
            QuicInitialAdmission::Admit {
                permit: 2,
                original_destination_id: [1, 2, 3, 4].into(),
            }
        );
        endpoint.reap_handshakes(200);
        assert_eq!(
            endpoint
                .resources
                .as_ref()
                .unwrap()
                .active_count(GitdWorkClass::Handshake),
            0
        );
        assert!(endpoint.resource_handshake_permits.is_empty());
    }

    #[test]
    fn endpoint_owns_bounded_connection_lifecycle_and_packet_spaces() {
        let mut endpoint = endpoint(1, 8);
        endpoint.configure_resource_controller(GitdResourceController::new(2).unwrap());
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
        assert_eq!(
            endpoint
                .resources
                .as_ref()
                .unwrap()
                .active_count(GitdWorkClass::OpenConnection),
            1
        );
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
        assert_eq!(
            endpoint
                .resources
                .as_ref()
                .unwrap()
                .active_count(GitdWorkClass::OpenConnection),
            0
        );
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
                .dispatch_datagram(peer(999), &first_packet)
                .unwrap()
                .map(|datagram| datagram.route),
            Some(QuicEndpointRoute::Established {
                connection: first,
                path: QuicPathClassification::Candidate,
            })
        );
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
        assert_eq!(
            endpoint.metrics(),
            QuicEndpointMetrics {
                datagrams_received: 10,
                bytes_received: 47,
                datagrams_dropped: 5,
                new_initials: 0,
                handshake_datagrams: 2,
                established_datagrams: 3,
                candidate_path_datagrams: 1,
                retry_datagrams_sent: 0,
            }
        );
    }
}
