use mrml_http::{QuicError, QuicServerEndpoint};
use mrml_runtime::unix_time_seconds;

use crate::{GitdHttp3LifecycleEvent, GitdHttp3WorkerError, GitdHttp3WorkerPool};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp3ReactorError {
    Clock,
    Endpoint,
    Workers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp3ReactorStep {
    RetriedOrRejected,
    Submitted,
}

pub struct GitdHttp3Reactor {
    workers: GitdHttp3WorkerPool,
    estimated_handshake_memory_bytes: u64,
    connection_queue_capacity: usize,
}

impl GitdHttp3Reactor {
    pub fn new(
        workers: GitdHttp3WorkerPool,
        estimated_handshake_memory_bytes: u64,
        connection_queue_capacity: usize,
    ) -> Result<Self, GitdHttp3ReactorError> {
        validate_reactor_limits(estimated_handshake_memory_bytes, connection_queue_capacity)?;
        Ok(Self {
            workers,
            estimated_handshake_memory_bytes,
            connection_queue_capacity,
        })
    }

    pub fn reconcile(
        &self,
        endpoint: &mut QuicServerEndpoint,
    ) -> Result<usize, GitdHttp3ReactorError> {
        let mut reconciled = 0usize;
        loop {
            let event = match self.workers.try_event() {
                Ok(Some(event)) => event,
                Ok(None) => return Ok(reconciled),
                Err(GitdHttp3WorkerError::Closed) => {
                    return Err(GitdHttp3ReactorError::Workers);
                }
                Err(_) => return Err(GitdHttp3ReactorError::Workers),
            };
            apply_lifecycle_event(endpoint, event)?;
            reconciled = reconciled
                .checked_add(1)
                .ok_or(GitdHttp3ReactorError::Endpoint)?;
        }
    }

    /// Processes one new Initial. Known-connection datagrams are routed inside
    /// `receive_new_initial`; worker events are reconciled immediately before
    /// and after the blocking endpoint receive.
    pub fn step(
        &self,
        endpoint: &mut QuicServerEndpoint,
    ) -> Result<GitdHttp3ReactorStep, GitdHttp3ReactorError> {
        self.reconcile(endpoint)?;
        let datagram = endpoint
            .receive_new_initial()
            .map_err(|_| GitdHttp3ReactorError::Endpoint)?;
        self.reconcile(endpoint)?;
        let now = unix_time_seconds().ok_or(GitdHttp3ReactorError::Clock)?;
        let Some(job) = endpoint
            .admit_endpoint_datagram(
                datagram,
                now,
                self.estimated_handshake_memory_bytes,
                self.connection_queue_capacity,
            )
            .map_err(|_| GitdHttp3ReactorError::Endpoint)?
        else {
            return Ok(GitdHttp3ReactorStep::RetriedOrRejected);
        };
        match self.workers.submit(job) {
            Ok(()) => Ok(GitdHttp3ReactorStep::Submitted),
            Err(job) => {
                let connection = job.connection;
                let permit = job.permit;
                drop(job.listener);
                let _ = endpoint.remove_connection(connection);
                let _ = endpoint.release_handshake_permit(permit);
                Err(GitdHttp3ReactorError::Workers)
            }
        }
    }

    pub fn begin_drain(&self) {
        self.workers.begin_drain();
    }

    pub fn workers(&self) -> &GitdHttp3WorkerPool {
        &self.workers
    }

    pub fn shutdown(
        mut self,
        endpoint: &mut QuicServerEndpoint,
    ) -> Result<crate::GitdHttp3WorkerMetrics, GitdHttp3ReactorError> {
        self.begin_drain();
        endpoint.drain_connections();
        self.workers
            .finish_drain()
            .map_err(|_| GitdHttp3ReactorError::Workers)?;
        loop {
            match self.workers.try_event() {
                Ok(Some(event)) => apply_lifecycle_event(endpoint, event)?,
                Ok(None) => continue,
                Err(GitdHttp3WorkerError::Closed) => break,
                Err(_) => return Err(GitdHttp3ReactorError::Workers),
            }
        }
        Ok(self.workers.metrics())
    }
}

fn validate_reactor_limits(
    estimated_handshake_memory_bytes: u64,
    connection_queue_capacity: usize,
) -> Result<(), GitdHttp3ReactorError> {
    if !(64 * 1024..=16 * 1024 * 1024).contains(&estimated_handshake_memory_bytes)
        || connection_queue_capacity == 0
        || connection_queue_capacity > 256
    {
        return Err(GitdHttp3ReactorError::Endpoint);
    }
    Ok(())
}

fn apply_lifecycle_event(
    endpoint: &mut QuicServerEndpoint,
    event: GitdHttp3LifecycleEvent,
) -> Result<(), GitdHttp3ReactorError> {
    match event {
        GitdHttp3LifecycleEvent::HandshakeFinished {
            connection,
            permit,
            established,
        } => {
            let established_result = if established {
                endpoint.mark_established_at(
                    connection,
                    unix_time_seconds().ok_or(GitdHttp3ReactorError::Clock)?,
                )
            } else {
                Err(QuicError::HandshakeConfirmation)
            };
            endpoint
                .release_handshake_permit(permit)
                .map_err(|_| GitdHttp3ReactorError::Endpoint)?;
            if established_result.is_err() {
                ignore_missing_connection(endpoint.remove_connection(connection))?;
            }
            Ok(())
        }
        GitdHttp3LifecycleEvent::ConnectionClosed { connection } => {
            ignore_missing_connection(endpoint.remove_connection(connection))
        }
    }
}

fn ignore_missing_connection(result: Result<(), QuicError>) -> Result<(), GitdHttp3ReactorError> {
    match result {
        Ok(()) | Err(QuicError::ConnectionId) => Ok(()),
        Err(_) => Err(GitdHttp3ReactorError::Endpoint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reactor_resource_envelope_is_bounded() {
        for (memory, queue) in [
            (64 * 1024 - 1, 1),
            (16 * 1024 * 1024 + 1, 1),
            (64 * 1024, 0),
            (64 * 1024, 257),
        ] {
            assert_eq!(
                validate_reactor_limits(memory, queue),
                Err(GitdHttp3ReactorError::Endpoint)
            );
        }
        assert_eq!(validate_reactor_limits(256 * 1024, 64), Ok(()));
    }
}
