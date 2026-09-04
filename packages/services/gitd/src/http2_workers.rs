use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use mrml_http::Http2ServerConnection;
use mrml_runtime::{blocking_channel, spawn_joinable, JoinHandle, Sender, Vector};
use mrml_tls::TlsServerStream;

use crate::{
    serve_gitd_http2_connection_with_drain, AdmittedTcpSocket, GitdComposedService,
    GitdTlsConfigStore,
};

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
    jobs: Option<Sender<AdmittedTcpSocket>>,
    workers: Vector<JoinHandle>,
    counters: Arc<WorkerCounters>,
    draining: Arc<AtomicBool>,
}

impl GitdHttp2WorkerPool {
    pub fn new(
        service: &GitdComposedService,
        tls: Arc<GitdTlsConfigStore>,
        worker_count: usize,
        queue_capacity: usize,
        maximum_connections: usize,
        cache_bytes_per_worker: usize,
        maximum_body_bytes: u64,
        connection_timeout_millis: u64,
    ) -> Result<Self, GitdHttp2WorkerError> {
        validate_limits(
            worker_count,
            queue_capacity,
            maximum_connections,
            cache_bytes_per_worker,
            maximum_body_bytes,
            connection_timeout_millis,
        )?;
        let (jobs, receiver) = blocking_channel::<AdmittedTcpSocket>(queue_capacity);
        let counters = Arc::new(WorkerCounters::default());
        let draining = Arc::new(AtomicBool::new(false));
        let mut workers =
            Vector::with_capacity(worker_count).map_err(|_| GitdHttp2WorkerError::Thread)?;
        for _ in 0..worker_count {
            let mut edge = match service.worker_edge(cache_bytes_per_worker) {
                Ok(edge) => edge,
                Err(_) => {
                    drop(jobs);
                    let _ = retire_workers(workers);
                    return Err(GitdHttp2WorkerError::Edge);
                }
            };
            let receiver = receiver.clone();
            let tls = tls.clone();
            let worker_counters = counters.clone();
            let worker_draining = draining.clone();
            let worker = match spawn_joinable(move || {
                while let Ok(admitted) = receiver.recv() {
                    if worker_draining.load(Ordering::Acquire) {
                        break;
                    }
                    if admitted.is_expired() {
                        admitted.record_expired();
                        continue;
                    }
                    let (socket, connection_permit) = admitted.into_parts();
                    let handshake_permit = match connection_permit.try_begin_handshake() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    let (_, config) = match tls.snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(_) => {
                            increment(&worker_counters.tls_failures);
                            eprintln!("component=mrml-gitd event=http2_tls_failed");
                            continue;
                        }
                    };
                    let tls_stream = TlsServerStream::accept_with_timeout(
                        socket,
                        &config,
                        connection_timeout_millis,
                    );
                    drop(handshake_permit);
                    let tls_stream = match tls_stream {
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
                            eprintln!("component=mrml-gitd event=http2_protocol_failed");
                            continue;
                        }
                    };
                    if let Err(error) = serve_gitd_http2_connection_with_drain(
                        &mut edge,
                        &mut connection,
                        maximum_body_bytes,
                        &worker_draining,
                    ) {
                        increment(&worker_counters.application_failures);
                        eprintln!(
                            "component=mrml-gitd event={}",
                            match error {
                                crate::GitdHttp2StreamError::Transport => "http2_transport_failed",
                                crate::GitdHttp2StreamError::Prepare(_) => "http2_prepare_failed",
                                crate::GitdHttp2StreamError::Backend(error) => match error {
                                    mrml_http::BackendError::MalformedIdentifier
                                    | mrml_http::BackendError::MalformedPath
                                    | mrml_http::BackendError::MalformedRevision => {
                                        "http2_backend_malformed"
                                    }
                                    mrml_http::BackendError::NotFound => "http2_backend_not_found",
                                    mrml_http::BackendError::Private => "http2_backend_private",
                                    mrml_http::BackendError::StaleGeneration => {
                                        "http2_backend_stale_generation"
                                    }
                                    mrml_http::BackendError::ResourceLimit => {
                                        "http2_backend_resource_limit"
                                    }
                                    mrml_http::BackendError::Unsupported => {
                                        "http2_backend_unsupported"
                                    }
                                    mrml_http::BackendError::Storage => "http2_backend_storage",
                                },
                            }
                        );
                    }
                }
            }) {
                Ok(worker) => worker,
                Err(_) => {
                    drop(jobs);
                    let _ = retire_workers(workers);
                    return Err(GitdHttp2WorkerError::Thread);
                }
            };
            workers.push(worker);
        }
        Ok(Self {
            jobs: Some(jobs),
            workers,
            counters,
            draining,
        })
    }

    pub fn submit(&self, socket: AdmittedTcpSocket) -> Result<(), GitdHttp2WorkerError> {
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

    pub fn shutdown(mut self) -> Result<GitdHttp2WorkerMetrics, GitdHttp2WorkerError> {
        self.retire()?;
        Ok(self.metrics())
    }

    fn retire(&mut self) -> Result<(), GitdHttp2WorkerError> {
        self.draining.store(true, Ordering::Release);
        self.jobs.take();
        let workers = core::mem::take(&mut self.workers);
        if retire_workers(workers) {
            Ok(())
        } else {
            Err(GitdHttp2WorkerError::Thread)
        }
    }
}

impl Drop for GitdHttp2WorkerPool {
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
    connection_timeout_millis: u64,
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
        || !(1_000..=300_000).contains(&connection_timeout_millis)
    {
        return Err(GitdHttp2WorkerError::Limit);
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
            (0, 1, 2, 1024 * 1024, 1, 1_000),
            (65, 1, 66, 1024 * 1024, 1, 1_000),
            (1, 0, 1, 1024 * 1024, 1, 1_000),
            (1, 65_537, 65_536, 1024 * 1024, 1, 1_000),
            (1, 1, 1, 1024 * 1024, 1, 1_000),
            (1, 1, 2, 1024 * 1024 - 1, 1, 1_000),
            (1, 1, 2, 1024 * 1024, 0, 1_000),
            (1, 1, 2, 1024 * 1024, 1, 999),
            (1, 1, 2, 1024 * 1024, 1, 300_001),
        ] {
            assert_eq!(
                validate_limits(
                    invalid.0, invalid.1, invalid.2, invalid.3, invalid.4, invalid.5,
                ),
                Err(GitdHttp2WorkerError::Limit)
            );
        }
        assert_eq!(
            validate_limits(64, 65_472, 65_536, 1024 * 1024, u64::MAX, 300_000),
            Ok(())
        );
    }
}
