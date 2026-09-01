use crate::{
    CertificateLifecycleAuthorizer, CertificateLifecycleProvider, MAX_MANAGED_STATUS_BYTES,
    ManagedIdentityStatus, ManagedStatusCodecError, TlsIdentityId, decode_managed_identity_status,
    dispatch_lifecycle_call,
};
use mrml_interface_certificate_lifecycle_v1 as abi;
use mrml_runtime::{NetError, TcpListener, TcpStream};

pub const MAX_HOSTED_LIFECYCLE_MEMORY: usize = 16 * 1024;
const HEADER_BYTES: usize = 16;
const REQUEST_MAGIC: &[u8; 8] = b"MRMLCLR1";
const RESPONSE_MAGIC: &[u8; 8] = b"MRMLCLS1";
const SESSION_MAGIC: &[u8; 8] = b"MRMLCAP1";
const SESSION_ACCEPTED: &[u8; 8] = b"MRMLOK01";
const IO_TIMEOUT_MILLIS: u64 = 2_000;
const MAX_FRAME_BYTES: usize = abi::IDENTITY_OPERATION_REQUEST_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedLifecycleTransportError {
    Network(NetError),
    InvalidHeader,
    InvalidFrame,
    MemoryLimit,
    OutputLengthMismatch,
    Protocol(abi::ProtocolError),
    RemoteStatus(abi::StatusError),
    Status(ManagedStatusCodecError),
    InvalidSessionCapability,
    SessionDenied,
}

/// One-use out-of-band authority for accepting a hosted lifecycle session.
/// The listener address identifies the service but does not authorize it.
pub struct HostedLifecycleSessionCapability {
    secret: [u8; 32],
    consumed: bool,
}

impl HostedLifecycleSessionCapability {
    pub fn new(secret: [u8; 32]) -> Result<Self, HostedLifecycleTransportError> {
        if secret == [0; 32] {
            return Err(HostedLifecycleTransportError::InvalidSessionCapability);
        }
        Ok(Self {
            secret,
            consumed: false,
        })
    }

    pub fn accept_one(
        &mut self,
        listener: &TcpListener,
    ) -> Result<HostedLifecycleServer, HostedLifecycleTransportError> {
        if self.consumed {
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        self.consumed = true;
        let mut stream = listener
            .accept()
            .map_err(HostedLifecycleTransportError::Network)?;
        configure(&mut stream)?;
        let mut request = [0u8; 40];
        let read_result = stream.read_exact(&mut request);
        let mut difference = 0u8;
        for (presented, expected) in request[8..].iter().zip(self.secret) {
            difference |= presented ^ expected;
        }
        self.secret.fill(0);
        let accepted = read_result.is_ok() && &request[..8] == SESSION_MAGIC && difference == 0;
        request.fill(0);
        if !accepted {
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        stream
            .write_all(SESSION_ACCEPTED)
            .map_err(HostedLifecycleTransportError::Network)?;
        Ok(HostedLifecycleServer { stream })
    }
}

impl Drop for HostedLifecycleSessionCapability {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Client over one connection already authorized and delivered by the host
/// supervisor. Addresses, ports, paths, and request fields never authorize a
/// lifecycle operation.
pub struct HostedLifecycleClient {
    stream: TcpStream,
}

impl HostedLifecycleClient {
    pub fn connect_session(
        ip: [u8; 4],
        port: u16,
        mut capability: [u8; 32],
    ) -> Result<Self, HostedLifecycleTransportError> {
        if capability == [0; 32] || port == 0 {
            capability.fill(0);
            return Err(HostedLifecycleTransportError::InvalidSessionCapability);
        }
        let stream =
            TcpStream::connect(ip, port).map_err(HostedLifecycleTransportError::Network)?;
        let mut client = Self::from_authorized_stream(stream)?;
        let mut request = [0u8; 40];
        request[..8].copy_from_slice(SESSION_MAGIC);
        request[8..].copy_from_slice(&capability);
        capability.fill(0);
        let result = client.stream.write_all(&request);
        request.fill(0);
        result.map_err(HostedLifecycleTransportError::Network)?;
        let mut response = [0u8; 8];
        client
            .stream
            .read_exact(&mut response)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &response != SESSION_ACCEPTED {
            response.fill(0);
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        response.fill(0);
        Ok(client)
    }

    pub fn from_authorized_stream(
        mut stream: TcpStream,
    ) -> Result<Self, HostedLifecycleTransportError> {
        configure(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn call(
        &mut self,
        frame: &[u8],
        memory: &mut [u8],
    ) -> Result<[u8; abi::RESPONSE_BYTES], HostedLifecycleTransportError> {
        validate_frame_length(frame.len())?;
        if memory.is_empty() || memory.len() > MAX_HOSTED_LIFECYCLE_MEMORY {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let mut header = [0u8; HEADER_BYTES];
        header[..8].copy_from_slice(REQUEST_MAGIC);
        header[8..10].copy_from_slice(&(frame.len() as u16).to_be_bytes());
        header[10..12].copy_from_slice(&(memory.len() as u16).to_be_bytes());
        self.stream
            .write_all(&header)
            .and_then(|_| self.stream.write_all(frame))
            .and_then(|_| self.stream.write_all(memory))
            .map_err(HostedLifecycleTransportError::Network)?;
        self.stream
            .read_exact(&mut header)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &header[..8] != RESPONSE_MAGIC || header[12..] != [0; 4] {
            return Err(HostedLifecycleTransportError::InvalidHeader);
        }
        let response_length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let memory_length = usize::from(u16::from_be_bytes([header[10], header[11]]));
        if response_length != abi::RESPONSE_BYTES || memory_length != memory.len() {
            return Err(HostedLifecycleTransportError::OutputLengthMismatch);
        }
        let mut response = [0u8; abi::RESPONSE_BYTES];
        self.stream
            .read_exact(&mut response)
            .and_then(|_| self.stream.read_exact(memory))
            .map_err(HostedLifecycleTransportError::Network)?;
        Ok(response)
    }

    pub fn identity_status(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<ManagedIdentityStatus, HostedLifecycleTransportError> {
        const OUTPUT_AT: usize = 32;
        let mut memory = [0u8; OUTPUT_AT + MAX_MANAGED_STATUS_BYTES];
        memory[..16].copy_from_slice(&identity.0);
        let frame = abi::encode_status_request(abi::StatusRequest {
            scope: abi::SCOPE_IDENTITY,
            object_identity: abi::BorrowedReadView::within(0, 16, memory.len() as u64).unwrap(),
            output: abi::BorrowedWriteView::within(
                OUTPUT_AT as u64,
                MAX_MANAGED_STATUS_BYTES as u64,
                memory.len() as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let response = self.call(&frame, &mut memory)?;
        let response = abi::decode_status_response(&response, MAX_MANAGED_STATUS_BYTES as u64)
            .map_err(HostedLifecycleTransportError::Protocol)?
            .map_err(HostedLifecycleTransportError::RemoteStatus)?;
        let written = usize::try_from(response.written)
            .map_err(|_| HostedLifecycleTransportError::OutputLengthMismatch)?;
        decode_managed_identity_status(&memory[OUTPUT_AT..OUTPUT_AT + written])
            .map_err(HostedLifecycleTransportError::Status)
    }
}

/// Server over one connection already authorized and delivered by the host
/// supervisor. The operation authorizer remains mandatory and exact.
pub struct HostedLifecycleServer {
    stream: TcpStream,
}

impl HostedLifecycleServer {
    pub fn from_authorized_stream(
        mut stream: TcpStream,
    ) -> Result<Self, HostedLifecycleTransportError> {
        configure(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn serve_one<A: CertificateLifecycleAuthorizer, P: CertificateLifecycleProvider>(
        &mut self,
        authorizer: &A,
        provider: &mut P,
    ) -> Result<(), HostedLifecycleTransportError> {
        let mut header = [0u8; HEADER_BYTES];
        self.stream
            .read_exact(&mut header)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &header[..8] != REQUEST_MAGIC || header[12..] != [0; 4] {
            return Err(HostedLifecycleTransportError::InvalidHeader);
        }
        let frame_length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let memory_length = usize::from(u16::from_be_bytes([header[10], header[11]]));
        validate_frame_length(frame_length)?;
        if memory_length == 0 || memory_length > MAX_HOSTED_LIFECYCLE_MEMORY {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let mut frame = [0u8; MAX_FRAME_BYTES];
        let mut memory = [0u8; MAX_HOSTED_LIFECYCLE_MEMORY];
        self.stream
            .read_exact(&mut frame[..frame_length])
            .and_then(|_| self.stream.read_exact(&mut memory[..memory_length]))
            .map_err(HostedLifecycleTransportError::Network)?;
        let response = dispatch_lifecycle_call(
            authorizer,
            provider,
            &frame[..frame_length],
            &mut memory[..memory_length],
        )
        .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        frame.fill(0);
        header.fill(0);
        header[..8].copy_from_slice(RESPONSE_MAGIC);
        header[8..10].copy_from_slice(&(abi::RESPONSE_BYTES as u16).to_be_bytes());
        header[10..12].copy_from_slice(&(memory_length as u16).to_be_bytes());
        let result = self
            .stream
            .write_all(&header)
            .and_then(|_| self.stream.write_all(&response))
            .and_then(|_| self.stream.write_all(&memory[..memory_length]))
            .map_err(HostedLifecycleTransportError::Network);
        memory.fill(0);
        result
    }
}

fn configure(stream: &mut TcpStream) -> Result<(), HostedLifecycleTransportError> {
    stream
        .set_read_timeout_millis(IO_TIMEOUT_MILLIS)
        .and_then(|_| stream.set_write_timeout_millis(IO_TIMEOUT_MILLIS))
        .map_err(HostedLifecycleTransportError::Network)
}

fn validate_frame_length(length: usize) -> Result<(), HostedLifecycleTransportError> {
    if length == abi::STATUS_REQUEST_BYTES
        || length == abi::ACCOUNT_OPERATION_REQUEST_BYTES
        || length == abi::IDENTITY_OPERATION_REQUEST_BYTES
    {
        Ok(())
    } else {
        Err(HostedLifecycleTransportError::InvalidFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_runtime::{Shared, TcpListener};

    struct Authorizer;
    impl CertificateLifecycleAuthorizer for Authorizer {
        fn authorize_status(&self, _: u32, _: &[u8]) -> bool {
            true
        }
        fn authorize_account(&self, operation: u32, generation: u64, request: &[u8]) -> bool {
            operation == abi::ACCOUNT_UPDATE && generation == 7 && request == b"exact"
        }
        fn authorize_identity(&self, _: u32, _: &[u8], _: u64, _: &[u8]) -> bool {
            false
        }
        fn authorize_backup(&self, _: u32, _: u64, _: &[u8]) -> bool {
            false
        }
    }

    struct Provider;
    impl CertificateLifecycleProvider for Provider {
        fn status(
            &mut self,
            _: u32,
            identity: &[u8],
            output: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            let identity: [u8; 16] = identity
                .try_into()
                .map_err(|_| abi::StatusError::InvalidRequest)?;
            let written = crate::encode_managed_identity_status(
                crate::ManagedIdentityStatus {
                    identity: TlsIdentityId(identity),
                    policy_generation: 7,
                    active: None,
                    renewal: None,
                    renewal_lease: None,
                    replacement: None,
                },
                output,
            )
            .map_err(|_| abi::StatusError::OutputTooSmall)?;
            Ok(abi::StatusResponse {
                written: written as u64,
                state_generation: 7,
            })
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            output: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            output[..2].copy_from_slice(b"ok");
            Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 8,
            })
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            unreachable!()
        }
        fn backup_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            unreachable!()
        }
    }

    #[test]
    fn preauthorized_stream_carries_exact_bounded_lifecycle_call() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(
            mrml_runtime::spawn_detached(move || {
                let stream = server_listener.accept().unwrap();
                let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
                server.serve_one(&Authorizer, &mut Provider).unwrap();
            })
            .is_ok()
        );
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut memory = [0u8; 64];
        memory[..5].copy_from_slice(b"exact");
        let frame = abi::encode_account_operation_request(abi::AccountOperationRequest {
            operation: abi::ACCOUNT_UPDATE,
            policy_generation: 7,
            request: abi::BorrowedReadView::within(0, 5, 64).unwrap(),
            output: abi::BorrowedWriteView::within(32, 32, 64).unwrap(),
        })
        .unwrap();
        let response = client.call(&frame, &mut memory).unwrap();
        assert_eq!(
            abi::decode_account_operation_response(&response, 32),
            Ok(Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 8
            }))
        );
        assert_eq!(&memory[32..34], b"ok");
    }

    #[test]
    fn rejects_bounds_before_io() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut memory = [0u8; 1];
        assert_eq!(
            client.call(&[0; 7], &mut memory),
            Err(HostedLifecycleTransportError::InvalidFrame)
        );
        let mut oversized = [0u8; MAX_HOSTED_LIFECYCLE_MEMORY + 1];
        assert_eq!(
            client.call(&[0; abi::STATUS_REQUEST_BYTES], &mut oversized),
            Err(HostedLifecycleTransportError::MemoryLimit)
        );
    }

    #[test]
    fn typed_status_call_hides_borrowed_memory_layout_from_client() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(
            mrml_runtime::spawn_detached(move || {
                let stream = server_listener.accept().unwrap();
                let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
                server.serve_one(&Authorizer, &mut Provider).unwrap();
            })
            .is_ok()
        );
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let identity = TlsIdentityId([9; 16]);
        let status = client.identity_status(identity).unwrap();
        assert!(status.identity == identity);
        assert_eq!(status.policy_generation, 7);
        assert!(status.active.is_none());
    }

    #[test]
    fn one_use_session_capability_authorizes_live_status_without_address_authority() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(
            mrml_runtime::spawn_detached(move || {
                let mut capability = HostedLifecycleSessionCapability::new([0x5a; 32]).unwrap();
                let mut server = capability.accept_one(&server_listener).unwrap();
                server.serve_one(&Authorizer, &mut Provider).unwrap();
                assert!(matches!(
                    capability.accept_one(&server_listener),
                    Err(HostedLifecycleTransportError::SessionDenied)
                ));
            })
            .is_ok()
        );
        let mut client =
            HostedLifecycleClient::connect_session([127, 0, 0, 1], port, [0x5a; 32]).unwrap();
        let status = client.identity_status(TlsIdentityId([9; 16])).unwrap();
        assert_eq!(status.policy_generation, 7);
    }
}
