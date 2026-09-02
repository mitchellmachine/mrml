use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mrml_http::Http2ServerConnection;
use mrml_runtime::{JoinHandle, Sender, TcpStream, Vector, blocking_channel, spawn_joinable};
use mrml_tls::{TlsServerConfig, TlsServerStream};

use crate::{GitdComposedService, serve_gitd_http2_connection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp2WorkerError {
    Limit,
    Edge,
    Thread,
    Closed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitdHttp2WorkerMetrics {
    pub accepted: u64,
    pub tls_failures: u64,
    pub protocol_failures: u64,
    pub application_failures: u64,
}

#[derive(Default)]
struct WorkerCounters {
    accepted: AtomicU64,
    tls_failures: AtomicU64,
    protocol_failures: AtomicU64,
    application_failures: AtomicU64,
}

pub struct GitdHttp2WorkerPool {
    jobs: Option<Sender<TcpStream>>,
    workers: Vector<JoinHandle>,
    counters: Arc<WorkerCounters>,
}

impl GitdHttp2WorkerPool {
    pub fn new(
        service: &GitdComposedService,
        tls: Arc<TlsServerConfig>,
        worker_count: usize,
        queue_capacity: usize,
        maximum_connections: usize,
        cache_bytes_per_worker: usize,
        maximum_body_bytes: u64,
    ) -> Result<Self, GitdHttp2WorkerError> {
        validate_limits(
            worker_count,
            queue_capacity,
            maximum_connections,
            cache_bytes_per_worker,
            maximum_body_bytes,
        )?;
        let (jobs, receiver) = blocking_channel(queue_capacity);
        let counters = Arc::new(WorkerCounters::default());
        let mut workers =
            Vector::with_capacity(worker_count).map_err(|_| GitdHttp2WorkerError::Thread)?;
        for _ in 0..worker_count {
            let mut edge = match service.worker_edge(cache_bytes_per_worker) {
                Ok(edge) => edge,
                Err(_) => {
                    drop(jobs);
                    retire_workers(workers);
                    return Err(GitdHttp2WorkerError::Edge);
                }
            };
            let receiver = receiver.clone();
            let tls = tls.clone();
            let worker_counters = counters.clone();
            let worker = match spawn_joinable(move || {
                while let Ok(socket) = receiver.recv() {
                    let tls_stream = match TlsServerStream::accept(socket, &tls) {
                        Ok(stream) => stream,
                        Err(_) => {
                            increment(&worker_counters.tls_failures);
                            continue;
                        }
                    };
                    let mut connection = match Http2ServerConnection::accept(tls_stream) {
                        Ok(connection) => connection,
                        Err(_) => {
                            increment(&worker_counters.protocol_failures);
                            continue;
                        }
                    };
                    if serve_gitd_http2_connection(&mut edge, &mut connection, maximum_body_bytes)
                        .is_err()
                    {
                        increment(&worker_counters.application_failures);
                    }
                }
            }) {
                Ok(worker) => worker,
                Err(_) => {
                    drop(jobs);
                    retire_workers(workers);
                    return Err(GitdHttp2WorkerError::Thread);
                }
            };
            workers.push(worker);
        }
        Ok(Self {
            jobs: Some(jobs),
            workers,
            counters,
        })
    }

    pub fn submit(&self, socket: TcpStream) -> Result<(), GitdHttp2WorkerError> {
        self.jobs
            .as_ref()
            .ok_or(GitdHttp2WorkerError::Closed)?
            .send(socket)
            .map_err(|_| GitdHttp2WorkerError::Closed)?;
        increment(&self.counters.accepted);
        Ok(())
    }

    pub fn metrics(&self) -> GitdHttp2WorkerMetrics {
        GitdHttp2WorkerMetrics {
            accepted: self.counters.accepted.load(Ordering::Acquire),
            tls_failures: self.counters.tls_failures.load(Ordering::Acquire),
            protocol_failures: self.counters.protocol_failures.load(Ordering::Acquire),
            application_failures: self.counters.application_failures.load(Ordering::Acquire),
        }
    }
}

impl Drop for GitdHttp2WorkerPool {
    fn drop(&mut self) {
        self.jobs.take();
        let workers = core::mem::take(&mut self.workers);
        retire_workers(workers);
    }
}

fn validate_limits(
    worker_count: usize,
    queue_capacity: usize,
    maximum_connections: usize,
    cache_bytes_per_worker: usize,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp2WorkerError> {
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
        return Err(GitdHttp2WorkerError::Limit);
    }
    Ok(())
}

fn retire_workers(mut workers: Vector<JoinHandle>) {
    while let Some(worker) = workers.pop() {
        let _ = worker.join();
    }
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
                Err(GitdHttp2WorkerError::Limit)
            );
        }
        assert_eq!(
            validate_limits(64, 65_472, 65_536, 1024 * 1024, u64::MAX),
            Ok(())
        );
    }
}
