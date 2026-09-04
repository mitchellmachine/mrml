use std::sync::{Arc, Mutex};

use mrml_runtime::{Instant, SocketAddress, TcpStream, Vector};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TcpSourceIdentity {
    Ipv4([u8; 4]),
    Ipv6Prefix64([u8; 8]),
}

impl TcpSourceIdentity {
    pub const fn ipv4(address: [u8; 4]) -> Self {
        Self::Ipv4(address)
    }

    pub const fn ipv6_64(address: [u8; 16]) -> Self {
        Self::Ipv6Prefix64([
            address[0], address[1], address[2], address[3], address[4], address[5], address[6],
            address[7],
        ])
    }
}

impl From<SocketAddress> for TcpSourceIdentity {
    fn from(address: SocketAddress) -> Self {
        Self::ipv4(address.ip)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpAdmissionLimits {
    pub maximum_sources: usize,
    pub maximum_connections: u32,
    pub maximum_connections_per_source: u32,
    pub maximum_handshakes: u32,
    pub rate_capacity: u32,
    pub rate_refill_per_second: u32,
    pub source_retention_seconds: u64,
    pub maximum_queue_millis: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpAdmissionMetrics {
    pub admitted: u64,
    pub rejected_source_table: u64,
    pub rejected_rate: u64,
    pub rejected_source_connections: u64,
    pub rejected_global_connections: u64,
    pub rejected_handshakes: u64,
    pub expired_queued: u64,
    pub queued_wait_millis_total: u64,
    pub queued_wait_millis_maximum: u64,
    pub permit_release_errors: u64,
    pub active_connections: u32,
    pub active_handshakes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpAdmissionError {
    InvalidLimits,
    PeerIdentity,
    Rejected,
    State,
}

struct SourceBucket {
    source: TcpSourceIdentity,
    tokens: u32,
    last_tick: u64,
    active: u32,
}

struct TcpAdmissionState {
    limits: TcpAdmissionLimits,
    sources: Vector<SourceBucket>,
    metrics: TcpAdmissionMetrics,
}

#[derive(Clone)]
pub struct TcpAdmissionController {
    state: Arc<Mutex<TcpAdmissionState>>,
    started: Instant,
}

impl TcpAdmissionController {
    pub fn new(limits: TcpAdmissionLimits) -> Result<Self, TcpAdmissionError> {
        if limits.maximum_sources == 0
            || limits.maximum_sources > 65_536
            || limits.maximum_connections == 0
            || limits.maximum_connections > 65_536
            || limits.maximum_connections_per_source == 0
            || limits.maximum_connections_per_source > limits.maximum_connections
            || limits.maximum_handshakes == 0
            || limits.maximum_handshakes > limits.maximum_connections
            || limits.rate_capacity == 0
            || limits.rate_refill_per_second == 0
            || limits.source_retention_seconds == 0
            || !(1..=300_000).contains(&limits.maximum_queue_millis)
        {
            return Err(TcpAdmissionError::InvalidLimits);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(TcpAdmissionState {
                limits,
                sources: Vector::new(),
                metrics: TcpAdmissionMetrics::default(),
            })),
            started: Instant::now(),
        })
    }

    pub fn admit(&self, socket: TcpStream) -> Result<AdmittedTcpSocket, TcpAdmissionError> {
        let source = TcpSourceIdentity::from(
            socket
                .peer_address()
                .map_err(|_| TcpAdmissionError::PeerIdentity)?,
        );
        let permit = self.admit_source_at(source, self.tick())?;
        Ok(AdmittedTcpSocket {
            socket,
            permit,
            queued_at: Instant::now(),
            maximum_queue_millis: self.limits()?.maximum_queue_millis,
        })
    }

    pub fn metrics(&self) -> Result<TcpAdmissionMetrics, TcpAdmissionError> {
        self.state
            .lock()
            .map(|state| state.metrics)
            .map_err(|_| TcpAdmissionError::State)
    }

    fn limits(&self) -> Result<TcpAdmissionLimits, TcpAdmissionError> {
        self.state
            .lock()
            .map(|state| state.limits)
            .map_err(|_| TcpAdmissionError::State)
    }

    fn tick(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn admit_source_at(
        &self,
        source: TcpSourceIdentity,
        tick: u64,
    ) -> Result<TcpConnectionPermit, TcpAdmissionError> {
        let mut state = self.state.lock().map_err(|_| TcpAdmissionError::State)?;
        if state.metrics.active_connections >= state.limits.maximum_connections {
            increment(&mut state.metrics.rejected_global_connections);
            return Err(TcpAdmissionError::Rejected);
        }
        let index = match state
            .sources
            .binary_search_by_key(&source, |bucket| bucket.source)
        {
            Ok(index) => index,
            Err(_) => {
                if state.sources.len() >= state.limits.maximum_sources {
                    let retention = state.limits.source_retention_seconds;
                    let mut retained = Vector::with_capacity(state.sources.len())
                        .map_err(|_| TcpAdmissionError::State)?;
                    let previous = core::mem::take(&mut state.sources);
                    for bucket in previous {
                        if bucket.active != 0
                            || tick.saturating_sub(bucket.last_tick) < retention
                        {
                            retained.push(bucket);
                        }
                    }
                    state.sources = retained;
                }
                if state.sources.len() >= state.limits.maximum_sources {
                    increment(&mut state.metrics.rejected_source_table);
                    return Err(TcpAdmissionError::Rejected);
                }
                let index = state
                    .sources
                    .binary_search_by_key(&source, |bucket| bucket.source)
                    .unwrap_or_else(|index| index);
                let capacity = state.limits.rate_capacity;
                state
                    .sources
                    .try_insert(
                        index,
                        SourceBucket {
                            source,
                            tokens: capacity,
                            last_tick: tick,
                            active: 0,
                        },
                    )
                    .map_err(|_| TcpAdmissionError::State)?;
                index
            }
        };
        let capacity = state.limits.rate_capacity;
        let refill_per_second = state.limits.rate_refill_per_second;
        let per_source = state.limits.maximum_connections_per_source;
        let bucket = &mut state.sources[index];
        let refill = tick
            .saturating_sub(bucket.last_tick)
            .saturating_mul(u64::from(refill_per_second))
            .min(u64::from(u32::MAX)) as u32;
        bucket.tokens = bucket.tokens.saturating_add(refill).min(capacity);
        bucket.last_tick = tick;
        if bucket.active >= per_source {
            increment(&mut state.metrics.rejected_source_connections);
            return Err(TcpAdmissionError::Rejected);
        }
        if bucket.tokens == 0 {
            increment(&mut state.metrics.rejected_rate);
            return Err(TcpAdmissionError::Rejected);
        }
        bucket.tokens -= 1;
        bucket.active += 1;
        state.metrics.active_connections += 1;
        increment(&mut state.metrics.admitted);
        Ok(TcpConnectionPermit {
            controller: self.clone(),
            source,
        })
    }
}

pub struct AdmittedTcpSocket {
    socket: TcpStream,
    permit: TcpConnectionPermit,
    queued_at: Instant,
    maximum_queue_millis: u64,
}

impl AdmittedTcpSocket {
    pub fn is_expired(&self) -> bool {
        self.queued_at.elapsed().as_millis() >= u128::from(self.maximum_queue_millis)
    }

    pub fn into_parts(self) -> (TcpStream, TcpConnectionPermit) {
        let elapsed = self.queued_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        if let Ok(mut state) = self.permit.controller.state.lock() {
            state.metrics.queued_wait_millis_total = state
                .metrics
                .queued_wait_millis_total
                .saturating_add(elapsed);
            state.metrics.queued_wait_millis_maximum =
                state.metrics.queued_wait_millis_maximum.max(elapsed);
        }
        let Self { socket, permit, .. } = self;
        (socket, permit)
    }

    pub fn record_expired(&self) {
        if let Ok(mut state) = self.permit.controller.state.lock() {
            increment(&mut state.metrics.expired_queued);
        }
    }
}

pub struct TcpConnectionPermit {
    controller: TcpAdmissionController,
    source: TcpSourceIdentity,
}

impl TcpConnectionPermit {
    pub fn try_begin_handshake(&self) -> Result<TcpHandshakePermit, TcpAdmissionError> {
        let mut state = self
            .controller
            .state
            .lock()
            .map_err(|_| TcpAdmissionError::State)?;
        if state.metrics.active_handshakes >= state.limits.maximum_handshakes {
            increment(&mut state.metrics.rejected_handshakes);
            return Err(TcpAdmissionError::Rejected);
        }
        state.metrics.active_handshakes += 1;
        Ok(TcpHandshakePermit {
            controller: self.controller.clone(),
        })
    }
}

impl Drop for TcpConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.controller.state.lock() {
            if let Ok(index) = state
                .sources
                .binary_search_by_key(&self.source, |bucket| bucket.source)
            {
                if state.sources[index].active == 0 {
                    increment(&mut state.metrics.permit_release_errors);
                } else {
                    state.sources[index].active -= 1;
                }
            } else {
                increment(&mut state.metrics.permit_release_errors);
            }
            if state.metrics.active_connections == 0 {
                increment(&mut state.metrics.permit_release_errors);
            } else {
                state.metrics.active_connections -= 1;
            }
        }
    }
}

pub struct TcpHandshakePermit {
    controller: TcpAdmissionController,
}

impl Drop for TcpHandshakePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.controller.state.lock() {
            if state.metrics.active_handshakes == 0 {
                increment(&mut state.metrics.permit_release_errors);
            } else {
                state.metrics.active_handshakes -= 1;
            }
        }
    }
}

fn increment(value: &mut u64) {
    *value = value.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TcpAdmissionLimits {
        TcpAdmissionLimits {
            maximum_sources: 2,
            maximum_connections: 3,
            maximum_connections_per_source: 2,
            maximum_handshakes: 1,
            rate_capacity: 2,
            rate_refill_per_second: 1,
            source_retention_seconds: 10,
            maximum_queue_millis: 1_000,
        }
    }

    #[test]
    fn source_rate_connection_and_handshake_limits_release_on_drop() {
        let controller = TcpAdmissionController::new(limits()).unwrap();
        let source = TcpSourceIdentity::ipv4([192, 0, 2, 1]);
        let first = controller.admit_source_at(source, 0).unwrap();
        let second = controller.admit_source_at(source, 0).unwrap();
        assert!(controller.admit_source_at(source, 0).is_err());
        let handshake = first.try_begin_handshake().unwrap();
        assert!(second.try_begin_handshake().is_err());
        drop(handshake);
        assert!(second.try_begin_handshake().is_ok());
        drop(first);
        drop(second);
        let metrics = controller.metrics().unwrap();
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.active_handshakes, 0);
        assert_eq!(metrics.rejected_source_connections, 1);
        assert_eq!(metrics.rejected_handshakes, 1);
        assert_eq!(metrics.permit_release_errors, 0);
        assert!(controller.admit_source_at(source, 1).is_ok());
    }

    #[test]
    fn source_table_expires_only_inactive_old_entries_and_ipv6_is_prefix_bound() {
        let controller = TcpAdmissionController::new(limits()).unwrap();
        let active = controller
            .admit_source_at(TcpSourceIdentity::ipv4([192, 0, 2, 1]), 0)
            .unwrap();
        let stale = controller
            .admit_source_at(TcpSourceIdentity::ipv4([192, 0, 2, 2]), 0)
            .unwrap();
        drop(stale);
        assert!(
            controller
                .admit_source_at(TcpSourceIdentity::ipv4([192, 0, 2, 3]), 1)
                .is_err()
        );
        assert!(
            controller
                .admit_source_at(TcpSourceIdentity::ipv4([192, 0, 2, 3]), 10)
                .is_ok()
        );
        drop(active);
        assert_eq!(
            TcpSourceIdentity::ipv6_64([
                0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8
            ]),
            TcpSourceIdentity::ipv6_64([
                0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 9, 9, 9, 9, 9, 9, 9, 9
            ])
        );
    }

    #[test]
    fn invalid_limits_fail_before_state_is_constructed() {
        let mut invalid = limits();
        invalid.maximum_connections_per_source = invalid.maximum_connections + 1;
        assert!(matches!(
            TcpAdmissionController::new(invalid),
            Err(TcpAdmissionError::InvalidLimits)
        ));
        invalid = limits();
        invalid.maximum_queue_millis = 0;
        assert!(matches!(
            TcpAdmissionController::new(invalid),
            Err(TcpAdmissionError::InvalidLimits)
        ));
    }
}
