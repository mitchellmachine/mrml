use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use mrml_http::{Http3ServerConnection, QuicAdmittedHandshake, QuicConnectionHandle};
use mrml_runtime::{
    JoinHandle, Receiver, Sender, TryRecvError, Vector, blocking_channel, spawn_joinable,
};

use crate::{GitdComposedService, GitdTlsConfigStore, serve_gitd_http3_connection_with_drain};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp3WorkerError {
    Limit,
    Edge,
    Thread,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp3LifecycleEvent {
    HandshakeFinished {
        connection: QuicConnectionHandle,
        permit: u64,
        established: bool,
    },
    ConnectionClosed {
        connection: QuicConnectionHandle,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitdHttp3WorkerMetrics {
    pub accepted: u64,
    pub handshake_failures: u64,
    pub application_failures: u64,
}

#[derive(Default)]
struct WorkerCounters {
    accepted: AtomicU64,
    handshake_failures: AtomicU64,
    application_failures: AtomicU64,
}

pub struct GitdHttp3WorkerPool {
    jobs: Option<Sender<QuicAdmittedHandshake>>,
    events: Receiver<GitdHttp3LifecycleEvent>,
    workers: Vector<JoinHandle>,
    counters: Arc<WorkerCounters>,
    draining: Arc<AtomicBool>,
}

impl GitdHttp3WorkerPool {
    pub fn new(
        service: &GitdComposedService,
        tls: Arc<GitdTlsConfigStore>,
        worker_count: usize,
        queue_capacity: usize,
        maximum_connections: usize,
        cache_bytes_per_worker: usize,
        maximum_body_bytes: u64,
    ) -> Result<Self, GitdHttp3WorkerError> {
        validate_limits(
            worker_count,
            queue_capacity,
            maximum_connections,
            cache_bytes_per_worker,
            maximum_body_bytes,
        )?;
        let (jobs, receiver) = blocking_channel::<QuicAdmittedHandshake>(queue_capacity);
        let event_capacity = maximum_connections
            .checked_mul(2)
            .ok_or(GitdHttp3WorkerError::Limit)?;
        let (event_sender, events) =
            blocking_channel::<GitdHttp3LifecycleEvent>(event_capacity);
        let counters = Arc::new(WorkerCounters::default());
        let draining = Arc::new(AtomicBool::new(false));
        let mut workers =
            Vector::with_capacity(worker_count).map_err(|_| GitdHttp3WorkerError::Thread)?;
        for _ in 0..worker_count {
            let mut edge = match service.worker_edge(cache_bytes_per_worker) {
                Ok(edge) => edge,
                Err(_) => {
                    drop(jobs);
                    let _ = retire_workers(workers);
                    return Err(GitdHttp3WorkerError::Edge);
                }
            };
            let receiver = receiver.clone();
            let events = event_sender.clone();
            let tls = tls.clone();
            let worker_counters = counters.clone();
            let worker_draining = draining.clone();
            let worker = match spawn_joinable(move || {
                while let Ok(job) = receiver.recv() {
                    if worker_draining.load(Ordering::Acquire) {
                        let _ = events.send(GitdHttp3LifecycleEvent::HandshakeFinished {
                            connection: job.connection,
                            permit: job.permit,
                            established: false,
                        });
                        continue;
                    }
                    let config = match tls.snapshot() {
                        Ok((_, config)) => config,
                        Err(_) => {
                            increment(&worker_counters.handshake_failures);
                            let _ = events.send(GitdHttp3LifecycleEvent::HandshakeFinished {
                                connection: job.connection,
                                permit: job.permit,
                                established: false,
                            });
                            continue;
                        }
                    };
                    let mut connection = match Http3ServerConnection::accept(job.listener, &config) {
                        Ok(connection) => connection,
                        Err(_) => {
                            increment(&worker_counters.handshake_failures);
                            let _ = events.send(GitdHttp3LifecycleEvent::HandshakeFinished {
                                connection: job.connection,
                                permit: job.permit,
                                established: false,
                            });
                            continue;
                        }
                    };
                    if events
                        .send(GitdHttp3LifecycleEvent::HandshakeFinished {
                            connection: job.connection,
                            permit: job.permit,
                            established: true,
                        })
                        .is_err()
                    {
                        break;
                    }
                    if serve_gitd_http3_connection_with_drain(
                        &mut edge,
                        &mut connection,
                        maximum_body_bytes,
                        &worker_draining,
                    )
                    .is_err()
                    {
                        increment(&worker_counters.application_failures);
                    }
                    if events
                        .send(GitdHttp3LifecycleEvent::ConnectionClosed {
                            connection: job.connection,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }) {
                Ok(worker) => worker,
                Err(_) => {
                    drop(jobs);
                    let _ = retire_workers(workers);
                    return Err(GitdHttp3WorkerError::Thread);
                }
            };
            workers.push(worker);
        }
        drop(event_sender);
        Ok(Self {
            jobs: Some(jobs),
            events,
            workers,
            counters,
            draining,
        })
    }

    pub fn submit(
        &self,
        job: QuicAdmittedHandshake,
    ) -> Result<(), QuicAdmittedHandshake> {
        let Some(jobs) = &self.jobs else {
            return Err(job);
        };
        jobs.send(job).map_err(|error| error.0)?;
        increment(&self.counters.accepted);
        Ok(())
    }

    pub fn try_event(
        &self,
    ) -> Result<Option<GitdHttp3LifecycleEvent>, GitdHttp3WorkerError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(GitdHttp3WorkerError::Closed),
        }
    }

    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub fn metrics(&self) -> GitdHttp3WorkerMetrics {
        GitdHttp3WorkerMetrics {
            accepted: self.counters.accepted.load(Ordering::Acquire),
            handshake_failures: self.counters.handshake_failures.load(Ordering::Acquire),
            application_failures: self.counters.application_failures.load(Ordering::Acquire),
        }
    }

    pub fn shutdown(mut self) -> Result<GitdHttp3WorkerMetrics, GitdHttp3WorkerError> {
        self.retire()?;
        Ok(self.metrics())
    }

    pub(crate) fn finish_drain(&mut self) -> Result<(), GitdHttp3WorkerError> {
        self.retire()
    }

    fn retire(&mut self) -> Result<(), GitdHttp3WorkerError> {
        self.begin_drain();
        self.jobs.take();
        let workers = core::mem::take(&mut self.workers);
        if retire_workers(workers) {
            Ok(())
        } else {
            Err(GitdHttp3WorkerError::Thread)
        }
    }
}

impl Drop for GitdHttp3WorkerPool {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

fn validate_limits(
    worker_count: usize,
    queue_capacity: usize,
    maximum_connections: usize,
    cache_bytes_per_worker: usize,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp3WorkerError> {
    if worker_count == 0
        || worker_count > 64
        || queue_capacity == 0
        || queue_capacity > 65_536
        || maximum_connections == 0
        || maximum_connections > 65_536
        || worker_count
            .checked_add(queue_capacity)
            .is_none_or(|total| total > maximum_connections)
        || cache_bytes_per_worker < 1024 * 1024
        || cache_bytes_per_worker > 1024 * 1024 * 1024
        || maximum_body_bytes == 0
    {
        return Err(GitdHttp3WorkerError::Limit);
    }
    Ok(())
}

fn retire_workers(mut workers: Vector<JoinHandle>) -> bool {
    let mut retired = true;
    while let Some(worker) = workers.pop() {
        retired &= worker.join();
    }
    retired
}

fn increment(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        value.checked_add(1)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_and_queue_limits_are_exact_and_bounded() {
        for invalid in [
            (0, 1, 2, 1024 * 1024, 1),
            (65, 1, 66, 1024 * 1024, 1),
            (1, 0, 1, 1024 * 1024, 1),
            (1, 65_537, 65_536, 1024 * 1024, 1),
            (1, 1, 1, 1024 * 1024, 1),
            (1, 1, 2, 1024 * 1024 - 1, 1),
            (1, 1, 2, 1024 * 1024, 0),
        ] {
            assert_eq!(
                validate_limits(invalid.0, invalid.1, invalid.2, invalid.3, invalid.4),
                Err(GitdHttp3WorkerError::Limit)
            );
        }
        assert_eq!(
            validate_limits(64, 65_472, 65_536, 1024 * 1024, u64::MAX),
            Ok(())
        );
    }
}
