use crate::{
    CertificateChallengeProvider, CertificateIdentityProvider, CertificateLifecycleAuthorizer,
    CertificateLifecycleProvider, CertificateSigningProvider, dispatch_challenge_call,
    dispatch_identity_call, dispatch_lifecycle_call, dispatch_signing_call,
};

pub const MAX_CERTIFICATE_CALL_BYTES: usize = 208;
pub const MAX_CERTIFICATE_SHARED_BYTES: usize = 16_384;
const RESPONSE_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateNativeRoute {
    Signing,
    Identity,
    Challenge,
    Lifecycle,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedCertificateCall {
    pub route: CertificateNativeRoute,
    pub payload_length: usize,
}
pub trait CertificateNativeSyscalls {
    type Error;
    fn receive(
        &mut self,
        payload: &mut [u8; MAX_CERTIFICATE_CALL_BYTES],
    ) -> Result<ReceivedCertificateCall, Self::Error>;
    fn read_preinstalled_shared(
        &mut self,
        output: &mut [u8; MAX_CERTIFICATE_SHARED_BYTES],
    ) -> Result<usize, Self::Error>;
    fn write_preinstalled_shared(&mut self, offset: usize, input: &[u8])
    -> Result<(), Self::Error>;
    fn send_response(&mut self, response: &[u8; RESPONSE_BYTES]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateSyscallFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}
pub unsafe trait CertificateRawSyscall {
    unsafe fn invoke(&mut self, frame: &mut CertificateSyscallFrame);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateUserspaceSyscallError {
    InvalidLaunch,
    Kernel(u64),
    InvalidKernelReturn,
}
pub struct CertificateUserspaceSyscalls<R> {
    raw: R,
    endpoint: u64,
    caller: u64,
    shared: u64,
    shared_len: usize,
    route: CertificateNativeRoute,
}
impl<R> CertificateUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        endpoint: u64,
        caller: u64,
        shared: u64,
        shared_len: usize,
        route: u64,
        provider_generation: u64,
    ) -> Result<Self, CertificateUserspaceSyscallError> {
        let route = match route {
            1 => CertificateNativeRoute::Signing,
            2 => CertificateNativeRoute::Identity,
            3 => CertificateNativeRoute::Challenge,
            4 => CertificateNativeRoute::Lifecycle,
            _ => return Err(CertificateUserspaceSyscallError::InvalidLaunch),
        };
        if endpoint == 0
            || caller == 0
            || shared == 0
            || shared_len == 0
            || shared_len > MAX_CERTIFICATE_SHARED_BYTES
            || provider_generation == 0
        {
            return Err(CertificateUserspaceSyscallError::InvalidLaunch);
        }
        Ok(Self {
            raw,
            endpoint,
            caller,
            shared,
            shared_len,
            route,
        })
    }
    pub fn into_raw(self) -> R {
        self.raw
    }
}
impl<R: CertificateRawSyscall> CertificateNativeSyscalls for CertificateUserspaceSyscalls<R> {
    type Error = CertificateUserspaceSyscallError;
    fn receive(
        &mut self,
        payload: &mut [u8; MAX_CERTIFICATE_CALL_BYTES],
    ) -> Result<ReceivedCertificateCall, Self::Error> {
        let mut capability = 0u64;
        let mut f = CertificateSyscallFrame {
            rax: 5,
            rdi: payload.as_mut_ptr() as u64,
            rsi: payload.len() as u64,
            rdx: core::ptr::addr_of_mut!(capability) as u64,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut f) }
        if f.rax != 0 {
            return Err(CertificateUserspaceSyscallError::Kernel(f.rax));
        }
        let length = usize::try_from(f.rdx)
            .map_err(|_| CertificateUserspaceSyscallError::InvalidKernelReturn)?;
        if length == 0 || length > payload.len() || f.r10 != 0 {
            return Err(CertificateUserspaceSyscallError::InvalidKernelReturn);
        }
        Ok(ReceivedCertificateCall {
            route: self.route,
            payload_length: length,
        })
    }
    fn read_preinstalled_shared(
        &mut self,
        output: &mut [u8; MAX_CERTIFICATE_SHARED_BYTES],
    ) -> Result<usize, Self::Error> {
        shared_call(
            &mut self.raw,
            7,
            self.shared,
            0,
            &mut output[..self.shared_len],
        )?;
        Ok(self.shared_len)
    }
    fn write_preinstalled_shared(
        &mut self,
        offset: usize,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let end = offset
            .checked_add(input.len())
            .ok_or(CertificateUserspaceSyscallError::InvalidKernelReturn)?;
        if input.is_empty() || end > self.shared_len {
            return Err(CertificateUserspaceSyscallError::InvalidKernelReturn);
        }
        let mut f = CertificateSyscallFrame {
            rax: 8,
            rdi: self.shared,
            rsi: offset as u64,
            rdx: input.as_ptr() as u64,
            r10: input.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut f) }
        status(f.rax)
    }
    fn send_response(&mut self, response: &[u8; RESPONSE_BYTES]) -> Result<(), Self::Error> {
        let mut f = CertificateSyscallFrame {
            rax: 4,
            rdi: self.endpoint,
            rsi: self.caller,
            rdx: response.as_ptr() as u64,
            r10: response.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut f) }
        status(f.rax)
    }
}
fn shared_call<R: CertificateRawSyscall>(
    raw: &mut R,
    operation: u64,
    capability: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<(), CertificateUserspaceSyscallError> {
    let mut f = CertificateSyscallFrame {
        rax: operation,
        rdi: capability,
        rsi: offset,
        rdx: output.as_mut_ptr() as u64,
        r10: output.len() as u64,
        r8: 0,
        r9: 0,
    };
    unsafe { raw.invoke(&mut f) }
    status(f.rax)
}
fn status(value: u64) -> Result<(), CertificateUserspaceSyscallError> {
    if value == 0 {
        Ok(())
    } else {
        Err(CertificateUserspaceSyscallError::Kernel(value))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateNativeServiceError<E> {
    Syscall(E),
    InvalidEnvelope,
    InvalidFrame,
    UnauthorizedMutation,
}
pub struct CertificateNativeServiceLoop {
    payload: [u8; MAX_CERTIFICATE_CALL_BYTES],
    shared: [u8; MAX_CERTIFICATE_SHARED_BYTES],
    before: [u8; MAX_CERTIFICATE_SHARED_BYTES],
}
impl CertificateNativeServiceLoop {
    pub const fn new() -> Self {
        Self {
            payload: [0; MAX_CERTIFICATE_CALL_BYTES],
            shared: [0; MAX_CERTIFICATE_SHARED_BYTES],
            before: [0; MAX_CERTIFICATE_SHARED_BYTES],
        }
    }
    pub fn serve_once<S, A, SP, IP, CP, LP>(
        &mut self,
        syscalls: &mut S,
        authorizer: &A,
        signing: &mut SP,
        identity: &mut IP,
        challenge: &mut CP,
        lifecycle: &mut LP,
    ) -> Result<CertificateNativeRoute, CertificateNativeServiceError<S::Error>>
    where
        S: CertificateNativeSyscalls,
        A: CertificateLifecycleAuthorizer,
        SP: CertificateSigningProvider,
        IP: CertificateIdentityProvider,
        CP: CertificateChallengeProvider,
        LP: CertificateLifecycleProvider,
    {
        self.payload.fill(0);
        self.shared.fill(0);
        self.before.fill(0);
        let received = syscalls
            .receive(&mut self.payload)
            .map_err(CertificateNativeServiceError::Syscall)?;
        if received.payload_length == 0 || received.payload_length > MAX_CERTIFICATE_CALL_BYTES {
            return Err(CertificateNativeServiceError::InvalidEnvelope);
        }
        let shared_len = syscalls
            .read_preinstalled_shared(&mut self.shared)
            .map_err(CertificateNativeServiceError::Syscall)?;
        if shared_len == 0 || shared_len > MAX_CERTIFICATE_SHARED_BYTES {
            return Err(CertificateNativeServiceError::InvalidEnvelope);
        }
        self.before[..shared_len].copy_from_slice(&self.shared[..shared_len]);
        let frame = &self.payload[..received.payload_length];
        let memory = &mut self.shared[..shared_len];
        let response = match received.route {
            CertificateNativeRoute::Signing => dispatch_signing_call(signing, frame, memory)
                .map_err(|_| CertificateNativeServiceError::InvalidFrame)?,
            CertificateNativeRoute::Identity => dispatch_identity_call(identity, frame, memory)
                .map_err(|_| CertificateNativeServiceError::InvalidFrame)?,
            CertificateNativeRoute::Challenge => dispatch_challenge_call(challenge, frame, memory)
                .map_err(|_| CertificateNativeServiceError::InvalidFrame)?,
            CertificateNativeRoute::Lifecycle => {
                dispatch_lifecycle_call(authorizer, lifecycle, frame, memory)
                    .map_err(|_| CertificateNativeServiceError::InvalidFrame)?
            }
        };
        if let Some((start, end)) =
            changed_span(&self.before[..shared_len], &self.shared[..shared_len])
        {
            syscalls
                .write_preinstalled_shared(start, &self.shared[start..end])
                .map_err(CertificateNativeServiceError::Syscall)?
        }
        syscalls
            .send_response(&response)
            .map_err(CertificateNativeServiceError::Syscall)?;
        self.payload.fill(0);
        self.before.fill(0);
        Ok(received.route)
    }
    pub fn erase(&mut self) {
        self.payload.fill(0);
        self.shared.fill(0);
        self.before.fill(0)
    }
}
impl Default for CertificateNativeServiceLoop {
    fn default() -> Self {
        Self::new()
    }
}
fn changed_span(before: &[u8], after: &[u8]) -> Option<(usize, usize)> {
    if before.len() != after.len() {
        return None;
    }
    let start = before.iter().zip(after).position(|(a, b)| a != b)?;
    let last = before.iter().zip(after).rposition(|(a, b)| a != b)?;
    Some((start, last + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_certificate_challenge_v1 as challenge_abi;
    use mrml_interface_certificate_identity_v1 as identity_abi;
    use mrml_interface_certificate_lifecycle_v1 as lifecycle_abi;
    use mrml_interface_certificate_signing_v1 as signing_abi;
    struct Io {
        frame: [u8; MAX_CERTIFICATE_CALL_BYTES],
        len: usize,
        shared: [u8; MAX_CERTIFICATE_SHARED_BYTES],
        response: [u8; RESPONSE_BYTES],
    }
    impl CertificateNativeSyscalls for Io {
        type Error = ();
        fn receive(
            &mut self,
            p: &mut [u8; MAX_CERTIFICATE_CALL_BYTES],
        ) -> Result<ReceivedCertificateCall, ()> {
            p[..self.len].copy_from_slice(&self.frame[..self.len]);
            Ok(ReceivedCertificateCall {
                route: CertificateNativeRoute::Identity,
                payload_length: self.len,
            })
        }
        fn read_preinstalled_shared(
            &mut self,
            o: &mut [u8; MAX_CERTIFICATE_SHARED_BYTES],
        ) -> Result<usize, ()> {
            o[..256].copy_from_slice(&self.shared[..256]);
            Ok(256)
        }
        fn write_preinstalled_shared(&mut self, offset: usize, input: &[u8]) -> Result<(), ()> {
            self.shared[offset..offset + input.len()].copy_from_slice(input);
            Ok(())
        }
        fn send_response(&mut self, r: &[u8; RESPONSE_BYTES]) -> Result<(), ()> {
            self.response = *r;
            Ok(())
        }
    }
    struct Providers;
    impl CertificateIdentityProvider for Providers {
        fn describe(
            &mut self,
            _: &[u8],
            _: u64,
            o: &mut [u8],
        ) -> Result<identity_abi::DescribeResponse, identity_abi::DescribeError> {
            o[..2].copy_from_slice(b"ok");
            Ok(identity_abi::DescribeResponse {
                written: 2,
                current_generation: 5,
            })
        }
        fn read_chain(
            &mut self,
            _: &[u8],
            _: u64,
            _: u32,
            _: &mut [u8],
        ) -> Result<identity_abi::ReadChainResponse, identity_abi::ReadChainError> {
            unreachable!()
        }
        fn request_signing_route(
            &mut self,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: &mut [u8],
        ) -> Result<identity_abi::RequestSigningRouteResponse, identity_abi::RequestSigningRouteError>
        {
            unreachable!()
        }
        fn poll_generation(
            &mut self,
            _: &[u8],
            _: u64,
        ) -> Result<identity_abi::PollGenerationResponse, identity_abi::PollGenerationError>
        {
            unreachable!()
        }
    }
    impl CertificateSigningProvider for Providers {
        fn describe_public_key(
            &mut self,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: u64,
            _: &mut [u8],
        ) -> Result<signing_abi::DescribePublicKeyResponse, signing_abi::DescribePublicKeyError>
        {
            unreachable!()
        }
        fn sign_approved_digest(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: u64,
            _: &[u8; 32],
            _: &mut [u8],
        ) -> Result<signing_abi::SignResponse, signing_abi::SignError> {
            unreachable!()
        }
    }
    impl CertificateChallengeProvider for Providers {
        fn prepare(
            &mut self,
            _: crate::challenge_service::PreparedChallenge<'_>,
            _: &mut [u8],
        ) -> Result<challenge_abi::PrepareResponse, challenge_abi::PrepareError> {
            unreachable!()
        }
        fn activate(&mut self, _: &[u8]) -> Result<u64, challenge_abi::ActivateError> {
            unreachable!()
        }
        fn prepare_removal(&mut self, _: &[u8]) -> Result<u64, challenge_abi::PrepareRemovalError> {
            unreachable!()
        }
        fn commit_removal(&mut self, _: &[u8]) -> Result<u64, challenge_abi::CommitRemovalError> {
            unreachable!()
        }
        fn authoritative_state(
            &mut self,
            _: &[u8],
        ) -> Result<challenge_abi::AuthoritativeStateResponse, challenge_abi::AuthoritativeStateError>
        {
            unreachable!()
        }
    }
    impl CertificateLifecycleProvider for Providers {
        fn status(
            &mut self,
            _: u32,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<lifecycle_abi::StatusResponse, lifecycle_abi::StatusError> {
            unreachable!()
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<lifecycle_abi::AccountOperationResponse, lifecycle_abi::AccountOperationError>
        {
            unreachable!()
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<lifecycle_abi::IdentityOperationResponse, lifecycle_abi::IdentityOperationError>
        {
            unreachable!()
        }
        fn backup_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<lifecycle_abi::BackupOperationResponse, lifecycle_abi::BackupOperationError>
        {
            unreachable!()
        }
    }
    impl CertificateLifecycleAuthorizer for Providers {
        fn authorize_status(&self, _: u32, _: &[u8]) -> bool {
            false
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
    #[test]
    fn syscall_loop_uses_preinstalled_shared_memory_and_exact_route() {
        let mut io = Io {
            frame: [0; MAX_CERTIFICATE_CALL_BYTES],
            len: 0,
            shared: [0; MAX_CERTIFICATE_SHARED_BYTES],
            response: [0; RESPONSE_BYTES],
        };
        io.shared[..16].fill(1);
        let request = identity_abi::DescribeRequest {
            identity: identity_abi::BorrowedReadView::within(0, 16, 256).unwrap(),
            observed_generation: 4,
            output: identity_abi::BorrowedWriteView::within(32, 32, 256).unwrap(),
        };
        let frame = identity_abi::encode_describe_request(request).unwrap();
        io.frame[..frame.len()].copy_from_slice(&frame);
        io.len = frame.len();
        let mut loop_state = CertificateNativeServiceLoop::new();
        let a = Providers;
        let mut s = Providers;
        let mut i = Providers;
        let mut c = Providers;
        let mut l = Providers;
        assert_eq!(
            loop_state.serve_once(&mut io, &a, &mut s, &mut i, &mut c, &mut l),
            Ok(CertificateNativeRoute::Identity)
        );
        assert_eq!(&io.shared[32..34], b"ok");
        assert_eq!(
            identity_abi::decode_describe_response(&io.response, 32),
            Ok(Ok(identity_abi::DescribeResponse {
                written: 2,
                current_generation: 5
            }))
        );
        loop_state.erase();
    }

    struct Raw {
        request: [u8; MAX_CERTIFICATE_CALL_BYTES],
        request_len: usize,
        shared: [u8; 64],
        response: [u8; RESPONSE_BYTES],
    }
    unsafe impl CertificateRawSyscall for Raw {
        unsafe fn invoke(&mut self, f: &mut CertificateSyscallFrame) {
            match f.rax {
                5 => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.request.as_ptr(),
                            f.rdi as *mut u8,
                            self.request_len,
                        )
                    };
                    f.rax = 0;
                    f.rdx = self.request_len as u64;
                    f.r10 = 0
                }
                7 => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.shared.as_ptr().add(f.rsi as usize),
                            f.rdx as *mut u8,
                            f.r10 as usize,
                        )
                    };
                    f.rax = 0
                }
                8 => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            f.rdx as *const u8,
                            self.shared.as_mut_ptr().add(f.rsi as usize),
                            f.r10 as usize,
                        )
                    };
                    f.rax = 0
                }
                4 => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            f.rdx as *const u8,
                            self.response.as_mut_ptr(),
                            RESPONSE_BYTES,
                        )
                    };
                    f.rax = 0
                }
                _ => f.rax = 99,
            }
        }
    }
    #[test]
    fn concrete_userspace_adapter_binds_launch_authority() {
        let raw = Raw {
            request: [7; MAX_CERTIFICATE_CALL_BYTES],
            request_len: 96,
            shared: [3; 64],
            response: [0; RESPONSE_BYTES],
        };
        assert!(matches!(
            CertificateUserspaceSyscalls::new(raw, 1, 2, 3, 64, 99, 1),
            Err(CertificateUserspaceSyscallError::InvalidLaunch)
        ));
        let raw = Raw {
            request: [7; MAX_CERTIFICATE_CALL_BYTES],
            request_len: 96,
            shared: [3; 64],
            response: [0; RESPONSE_BYTES],
        };
        let mut sys = CertificateUserspaceSyscalls::new(raw, 1, 2, 3, 64, 2, 9).unwrap();
        let mut payload = [0; MAX_CERTIFICATE_CALL_BYTES];
        assert_eq!(
            sys.receive(&mut payload),
            Ok(ReceivedCertificateCall {
                route: CertificateNativeRoute::Identity,
                payload_length: 96
            })
        );
        let mut shared = [0; MAX_CERTIFICATE_SHARED_BYTES];
        assert_eq!(sys.read_preinstalled_shared(&mut shared), Ok(64));
        assert_eq!(&shared[..64], &[3; 64]);
        sys.write_preinstalled_shared(4, b"ok").unwrap();
        sys.send_response(&[5; RESPONSE_BYTES]).unwrap();
        let raw = sys.into_raw();
        assert_eq!(&raw.shared[4..6], b"ok");
        assert_eq!(raw.response, [5; RESPONSE_BYTES]);
    }
}
