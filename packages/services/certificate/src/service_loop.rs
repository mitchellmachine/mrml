use crate::{
    CertificateChallengeProvider, CertificateIdentityProvider, CertificateLifecycleAuthorizer,
    CertificateLifecycleProvider, dispatch_challenge_call, dispatch_identity_call,
    dispatch_lifecycle_call,
};
use mrml_interface_certificate_signing_v1 as abi;
use mrml_kernel::{Capability, ControlEvent, Endpoint, TaskId, TaskRuntime, TaskRuntimeError};

pub trait CertificateSigningProvider {
    fn describe_public_key(
        &mut self,
        identity: &[u8],
        identity_generation: u64,
        key_identity: &[u8; 32],
        route_generation: u64,
        output: &mut [u8],
    ) -> Result<abi::DescribePublicKeyResponse, abi::DescribePublicKeyError>;

    fn sign_approved_digest(
        &mut self,
        purpose: u32,
        identity: &[u8],
        identity_generation: u64,
        key_identity: &[u8; 32],
        route_generation: u64,
        approved_digest: &[u8; 32],
        output: &mut [u8],
    ) -> Result<abi::SignResponse, abi::SignError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum CertificateSigningServiceError {
    Runtime(TaskRuntimeError),
    PeerDied,
    UnexpectedSender,
    CapabilityShape,
    InvalidFrame,
}

pub fn dispatch_signing_call<P: CertificateSigningProvider>(
    provider: &mut P,
    frame: &[u8],
    memory: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], CertificateSigningServiceError> {
    match frame.len() {
        abi::DESCRIBE_PUBLIC_KEY_REQUEST_BYTES => {
            let exact: &[u8; abi::DESCRIBE_PUBLIC_KEY_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| CertificateSigningServiceError::InvalidFrame)?;
            let request = abi::decode_describe_public_key_request(exact, memory.len() as u64)
                .map_err(|_| CertificateSigningServiceError::InvalidFrame)?;
            let identity = copy_identity(memory, request.identity)?;
            let key_identity = copy_32(memory, request.key_identity)?;
            let output = write(memory, request.output)
                .ok_or(CertificateSigningServiceError::InvalidFrame)?;
            let result = provider.describe_public_key(
                &identity[..request.identity.length() as usize],
                request.identity_generation,
                &key_identity,
                request.route_generation,
                output,
            );
            if !valid_describe_result(&result, output.len()) {
                output.fill(0);
                return Ok(abi::encode_describe_public_key_response(Err(
                    abi::DescribePublicKeyError::KeyUnavailable,
                )));
            }
            if result.is_err() {
                output.fill(0);
            }
            Ok(abi::encode_describe_public_key_response(result))
        }
        abi::SIGN_REQUEST_BYTES => {
            let exact: &[u8; abi::SIGN_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| CertificateSigningServiceError::InvalidFrame)?;
            let request = abi::decode_sign_request(exact, memory.len() as u64)
                .map_err(|_| CertificateSigningServiceError::InvalidFrame)?;
            let identity = copy_identity(memory, request.identity)?;
            let key_identity = copy_32(memory, request.key_identity)?;
            let digest = copy_32(memory, request.approved_digest)?;
            let output = write(memory, request.output)
                .ok_or(CertificateSigningServiceError::InvalidFrame)?;
            let result = provider.sign_approved_digest(
                request.purpose,
                &identity[..request.identity.length() as usize],
                request.identity_generation,
                &key_identity,
                request.route_generation,
                &digest,
                output,
            );
            if !valid_sign_result(&result, output.len()) {
                output.fill(0);
                return Ok(abi::encode_sign_response(Err(
                    abi::SignError::SigningFailed,
                )));
            }
            if result.is_err() {
                output.fill(0);
            }
            Ok(abi::encode_sign_response(result))
        }
        _ => Err(CertificateSigningServiceError::InvalidFrame),
    }
}

pub fn serve_native_signing_once<
    P: CertificateSigningProvider,
    const TASKS: usize,
    const CAPS: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    provider: &mut P,
    shared_memory: &mut [u8],
) -> Result<(), CertificateSigningServiceError> {
    serve_native_once(
        runtime,
        caller,
        service,
        reply_endpoint,
        reply_capability,
        shared_memory,
        |frame, memory| dispatch_signing_call(provider, frame, memory).map_err(|_| ()),
    )
}

pub fn serve_native_identity_once<
    P: CertificateIdentityProvider,
    const TASKS: usize,
    const CAPS: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    provider: &mut P,
    shared_memory: &mut [u8],
) -> Result<(), CertificateSigningServiceError> {
    serve_native_once(
        runtime,
        caller,
        service,
        reply_endpoint,
        reply_capability,
        shared_memory,
        |frame, memory| dispatch_identity_call(provider, frame, memory).map_err(|_| ()),
    )
}
pub fn serve_native_challenge_once<
    P: CertificateChallengeProvider,
    const TASKS: usize,
    const CAPS: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    provider: &mut P,
    shared_memory: &mut [u8],
) -> Result<(), CertificateSigningServiceError> {
    serve_native_once(
        runtime,
        caller,
        service,
        reply_endpoint,
        reply_capability,
        shared_memory,
        |frame, memory| dispatch_challenge_call(provider, frame, memory).map_err(|_| ()),
    )
}
pub fn serve_native_lifecycle_once<
    A: CertificateLifecycleAuthorizer,
    P: CertificateLifecycleProvider,
    const TASKS: usize,
    const CAPS: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    authorizer: &A,
    provider: &mut P,
    shared_memory: &mut [u8],
) -> Result<(), CertificateSigningServiceError> {
    serve_native_once(
        runtime,
        caller,
        service,
        reply_endpoint,
        reply_capability,
        shared_memory,
        |frame, memory| {
            dispatch_lifecycle_call(authorizer, provider, frame, memory).map_err(|_| ())
        },
    )
}

fn serve_native_once<F, const TASKS: usize, const CAPS: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    shared_memory: &mut [u8],
    dispatch: F,
) -> Result<(), CertificateSigningServiceError>
where
    F: FnOnce(&[u8], &mut [u8]) -> Result<[u8; abi::RESPONSE_BYTES], ()>,
{
    let received = match runtime
        .receive_control(service)
        .map_err(CertificateSigningServiceError::Runtime)?
    {
        ControlEvent::Message(message) => message,
        ControlEvent::PeerDied(_) => return Err(CertificateSigningServiceError::PeerDied),
    };
    if received.sender() != caller {
        return Err(CertificateSigningServiceError::UnexpectedSender);
    }
    let message = received.into_message();
    message
        .authorize_no_capabilities()
        .map_err(|_| CertificateSigningServiceError::CapabilityShape)?;
    let response = dispatch(message.payload(), shared_memory)
        .map_err(|_| CertificateSigningServiceError::InvalidFrame)?;
    runtime
        .deliver_ipc(
            service,
            caller,
            reply_endpoint,
            reply_capability,
            &response,
            &[],
        )
        .map(|_| ())
        .map_err(CertificateSigningServiceError::Runtime)
}

fn valid_describe_result(
    result: &Result<abi::DescribePublicKeyResponse, abi::DescribePublicKeyError>,
    output: usize,
) -> bool {
    match result {
        Ok(value) => {
            value.written != 0
                && value.written <= output as u64
                && value.written <= 65
                && value.key_generation != 0
        }
        Err(_) => true,
    }
}
fn valid_sign_result(result: &Result<abi::SignResponse, abi::SignError>, output: usize) -> bool {
    match result {
        Ok(value) => {
            value.written != 0
                && value.written <= output as u64
                && value.written <= 72
                && value.signature_generation != 0
        }
        Err(_) => true,
    }
}
fn bounds(offset: u64, length: u64, total: usize) -> Option<(usize, usize)> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(length).ok()?;
    let end = start.checked_add(len)?;
    (end <= total).then_some((start, end))
}
fn read(memory: &[u8], view: abi::BorrowedReadView) -> Option<&[u8]> {
    let (start, end) = bounds(view.offset(), view.length(), memory.len())?;
    memory.get(start..end)
}
fn write(memory: &mut [u8], view: abi::BorrowedWriteView) -> Option<&mut [u8]> {
    let total = memory.len();
    let (start, end) = bounds(view.offset(), view.length(), total)?;
    memory.get_mut(start..end)
}
fn copy_32(
    memory: &[u8],
    view: abi::BorrowedReadView,
) -> Result<[u8; 32], CertificateSigningServiceError> {
    read(memory, view)
        .and_then(|v| v.try_into().ok())
        .ok_or(CertificateSigningServiceError::InvalidFrame)
}
fn copy_identity(
    memory: &[u8],
    view: abi::BorrowedReadView,
) -> Result<[u8; 16], CertificateSigningServiceError> {
    let source = read(memory, view).ok_or(CertificateSigningServiceError::InvalidFrame)?;
    let mut result = [0; 16];
    result
        .get_mut(..source.len())
        .ok_or(CertificateSigningServiceError::InvalidFrame)?
        .copy_from_slice(source);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{ObjectId, PhysAddr, Priority, Rights};

    struct Provider;
    impl CertificateSigningProvider for Provider {
        fn describe_public_key(
            &mut self,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: u64,
            output: &mut [u8],
        ) -> Result<abi::DescribePublicKeyResponse, abi::DescribePublicKeyError> {
            output[..2].copy_from_slice(&[4, 5]);
            Ok(abi::DescribePublicKeyResponse {
                written: 2,
                key_generation: 8,
            })
        }
        fn sign_approved_digest(
            &mut self,
            purpose: u32,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: u64,
            digest: &[u8; 32],
            output: &mut [u8],
        ) -> Result<abi::SignResponse, abi::SignError> {
            assert_eq!(purpose, abi::PURPOSE_ACME_ACCOUNT_JWS);
            output[..32].copy_from_slice(digest);
            Ok(abi::SignResponse {
                written: 32,
                signature_generation: 9,
            })
        }
    }
    fn context(root: u64, entry: u64, stack: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, stack).unwrap()
    }
    #[test]
    fn native_runtime_delivers_exact_bounded_signing_frame() {
        let mut runtime = TaskRuntime::<2, 4>::new(1000, 1).unwrap();
        let caller = runtime
            .create(Priority::NORMAL, context(0x1000, 0x2000, 0x3000))
            .unwrap();
        let service = runtime
            .create(Priority::NORMAL, context(0x4000, 0x5000, 0x6000))
            .unwrap();
        let request_object = ObjectId(71);
        let reply_object = ObjectId(72);
        let request_cap = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let reply_cap = runtime
            .capabilities_mut(service)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let mut memory = [0u8; 192];
        memory[..16].copy_from_slice(&[1; 16]);
        memory[16..48].copy_from_slice(&[2; 32]);
        memory[48..80].copy_from_slice(&[3; 32]);
        let request = abi::SignRequest {
            purpose: abi::PURPOSE_ACME_ACCOUNT_JWS,
            identity: abi::BorrowedReadView::within(0, 16, 192).unwrap(),
            identity_generation: 5,
            key_identity: abi::BorrowedReadView::within(16, 32, 192).unwrap(),
            route_generation: 6,
            approved_digest: abi::BorrowedReadView::within(48, 32, 192).unwrap(),
            output: abi::BorrowedWriteView::within(80, 72, 192).unwrap(),
        };
        let frame = abi::encode_sign_request(request).unwrap();
        let mut request_endpoint = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                caller,
                service,
                &mut request_endpoint,
                request_cap,
                &frame,
                &[],
            )
            .unwrap();
        let mut reply_endpoint = Endpoint::new(reply_object);
        serve_native_signing_once(
            &mut runtime,
            caller,
            service,
            &mut reply_endpoint,
            reply_cap,
            &mut Provider,
            &mut memory,
        )
        .unwrap();
        let message = match runtime.receive_control(caller).unwrap() {
            ControlEvent::Message(m) => m.into_message(),
            ControlEvent::PeerDied(_) => panic!(),
        };
        let response: &[u8; abi::RESPONSE_BYTES] = message.payload().try_into().unwrap();
        assert_eq!(
            abi::decode_sign_response(response, 72),
            Ok(Ok(abi::SignResponse {
                written: 32,
                signature_generation: 9
            }))
        );
        assert_eq!(&memory[80..112], &[3; 32]);
    }
}
