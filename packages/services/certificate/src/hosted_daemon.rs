use crate::{
    CertificateLifecycleAuthorizer, CertificateLifecycleProvider, HostedLifecycleServer,
    HostedLifecycleTransportError,
};

pub const MAX_HOSTED_LIFECYCLE_SESSIONS_PER_RUN: u64 = 1_000_000;

pub enum HostedLifecycleSupervisorEvent {
    AuthorizedSession(HostedLifecycleServer),
    Shutdown,
}

pub trait HostedLifecycleSupervisor {
    type Error;
    fn next_event(&mut self) -> Result<HostedLifecycleSupervisorEvent, Self::Error>;
}

pub trait HostedLifecycleSessionService {
    fn reconstruct_and_serve(
        &mut self,
        session: &mut HostedLifecycleServer,
    ) -> Result<(), HostedLifecycleTransportError>;
}

pub struct ReconstructingLifecycleService<F> {
    reconstruct: F,
}

impl<F> ReconstructingLifecycleService<F> {
    pub fn new(reconstruct: F) -> Self {
        Self { reconstruct }
    }
}

impl<F, A, P> HostedLifecycleSessionService for ReconstructingLifecycleService<F>
where
    F: FnMut() -> Result<(A, P), HostedLifecycleTransportError>,
    A: CertificateLifecycleAuthorizer,
    P: CertificateLifecycleProvider,
{
    fn reconstruct_and_serve(
        &mut self,
        session: &mut HostedLifecycleServer,
    ) -> Result<(), HostedLifecycleTransportError> {
        let (authorizer, mut provider) = (self.reconstruct)()?;
        session.serve_one(&authorizer, &mut provider)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum HostedLifecycleDaemonError<E> {
    InvalidSessionBudget,
    SessionBudgetExhausted,
    Supervisor(E),
    Session(HostedLifecycleTransportError),
}

pub fn run_hosted_lifecycle_daemon<S, D>(
    supervisor: &mut S,
    service: &mut D,
    session_budget: u64,
) -> Result<u64, HostedLifecycleDaemonError<S::Error>>
where
    S: HostedLifecycleSupervisor,
    D: HostedLifecycleSessionService,
{
    if session_budget == 0 || session_budget > MAX_HOSTED_LIFECYCLE_SESSIONS_PER_RUN {
        return Err(HostedLifecycleDaemonError::InvalidSessionBudget);
    }
    let mut served = 0u64;
    loop {
        if served == session_budget {
            return Err(HostedLifecycleDaemonError::SessionBudgetExhausted);
        }
        match supervisor
            .next_event()
            .map_err(HostedLifecycleDaemonError::Supervisor)?
        {
            HostedLifecycleSupervisorEvent::AuthorizedSession(mut session) => {
                service
                    .reconstruct_and_serve(&mut session)
                    .map_err(HostedLifecycleDaemonError::Session)?;
                served += 1;
            }
            HostedLifecycleSupervisorEvent::Shutdown => return Ok(served),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use mrml_interface_certificate_lifecycle_v1 as abi;
    use mrml_runtime::{Shared, SpinMutex, TcpListener, TcpStream};
    use std::{collections::VecDeque, vec::Vec};

    struct Authorizer;
    impl CertificateLifecycleAuthorizer for Authorizer {
        fn authorize_status(&self, scope: u32, object: &[u8]) -> bool {
            scope == abi::SCOPE_IDENTITY && object == b"identity"
        }
        fn authorize_account(&self, _: u32, _: u64, _: &[u8]) -> bool {
            false
        }
        fn authorize_identity(&self, _: u32, _: &[u8], _: u64, _: &[u8]) -> bool {
            false
        }
        fn authorize_backup(&self, _: u32, _: u64, _: &[u8]) -> bool {
            false
        }
    }

    struct Provider(u64);
    impl CertificateLifecycleProvider for Provider {
        fn status(
            &mut self,
            _: u32,
            _: &[u8],
            output: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            output[..8].copy_from_slice(&self.0.to_be_bytes());
            Ok(abi::StatusResponse {
                written: 8,
                state_generation: self.0,
            })
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            Err(abi::AccountOperationError::PermissionDenied)
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            Err(abi::IdentityOperationError::PermissionDenied)
        }
        fn backup_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            Err(abi::BackupOperationError::PermissionDenied)
        }
    }

    struct Supervisor(VecDeque<HostedLifecycleSupervisorEvent>);
    impl HostedLifecycleSupervisor for Supervisor {
        type Error = ();
        fn next_event(&mut self) -> Result<HostedLifecycleSupervisorEvent, Self::Error> {
            Ok(self
                .0
                .pop_front()
                .unwrap_or(HostedLifecycleSupervisorEvent::Shutdown))
        }
    }

    fn session_pair() -> (HostedLifecycleServer, TcpStream) {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let holder = Shared::new(SpinMutex::new(None));
        let accepted = holder.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            *accepted.lock() = Some(listener.accept().unwrap());
        })
        .is_ok());
        let client = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        loop {
            if let Some(stream) = holder.lock().take() {
                return (
                    HostedLifecycleServer::from_authorized_stream(stream).unwrap(),
                    client,
                );
            }
        }
    }

    #[test]
    fn daemon_reconstructs_provider_for_every_fresh_supervisor_session() {
        let (server_one, client_one) = session_pair();
        let (server_two, client_two) = session_pair();
        let mut supervisor = Supervisor(VecDeque::from(Vec::from([
            HostedLifecycleSupervisorEvent::AuthorizedSession(server_one),
            HostedLifecycleSupervisorEvent::AuthorizedSession(server_two),
            HostedLifecycleSupervisorEvent::Shutdown,
        ])));
        let generations = Shared::new(SpinMutex::new(0u64));
        let reconstruction_count = generations.clone();
        let mut service = ReconstructingLifecycleService::new(move || {
            let mut value = reconstruction_count.lock();
            *value += 1;
            Ok((Authorizer, Provider(*value)))
        });
        let worker = Shared::new(SpinMutex::new(None));
        let result = worker.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            *result.lock() = Some(run_hosted_lifecycle_daemon(
                &mut supervisor,
                &mut service,
                3,
            ));
        })
        .is_ok());
        for (client, expected) in [(client_one, 1u64), (client_two, 2u64)] {
            let mut hosted = crate::HostedLifecycleClient::from_authorized_stream(client).unwrap();
            let mut memory = [0u8; 72];
            memory[..8].copy_from_slice(b"identity");
            let frame = abi::encode_status_request(abi::StatusRequest {
                scope: abi::SCOPE_IDENTITY,
                object_identity: abi::BorrowedReadView::within(0, 8, 72).unwrap(),
                output: abi::BorrowedWriteView::within(64, 8, 72).unwrap(),
            })
            .unwrap();
            let response = hosted.call(&frame, &mut memory).unwrap();
            let decoded = abi::decode_status_response(&response, 8).unwrap().unwrap();
            assert_eq!(decoded.state_generation, expected);
            assert_eq!(
                u64::from_be_bytes(memory[64..72].try_into().unwrap()),
                expected
            );
        }
        loop {
            if let Some(result) = worker.lock().take() {
                assert_eq!(result, Ok(2));
                break;
            }
        }
        assert_eq!(*generations.lock(), 2);
    }

    #[test]
    fn daemon_rejects_invalid_session_budget() {
        let mut supervisor = Supervisor(VecDeque::new());
        let mut service = ReconstructingLifecycleService::new(|| Ok((Authorizer, Provider(1))));
        assert_eq!(
            run_hosted_lifecycle_daemon(&mut supervisor, &mut service, 0),
            Err(HostedLifecycleDaemonError::InvalidSessionBudget)
        );
    }
}
