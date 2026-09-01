use mrml_interface_certificate_lifecycle_v1 as abi;

pub trait CertificateLifecycleAuthorizer {
    fn authorize_status(&self, scope: u32, object_identity: &[u8]) -> bool;
    fn authorize_account(&self, operation: u32, policy_generation: u64, request: &[u8]) -> bool;
    fn authorize_identity(
        &self,
        operation: u32,
        identity: &[u8],
        policy_generation: u64,
        request: &[u8],
    ) -> bool;
    fn authorize_backup(&self, operation: u32, policy_generation: u64, request: &[u8]) -> bool;
}
pub trait CertificateLifecycleProvider {
    fn status(
        &mut self,
        scope: u32,
        object_identity: &[u8],
        output: &mut [u8],
    ) -> Result<abi::StatusResponse, abi::StatusError>;
    fn account_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError>;
    fn identity_operation(
        &mut self,
        operation: u32,
        identity: &[u8],
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError>;
    fn backup_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleDispatchError {
    InvalidFrame,
}
pub fn dispatch_lifecycle_call<
    A: CertificateLifecycleAuthorizer,
    P: CertificateLifecycleProvider,
>(
    a: &A,
    p: &mut P,
    frame: &[u8],
    memory: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], LifecycleDispatchError> {
    match operation(frame)? {
        abi::OP_STATUS => {
            let exact: &[u8; abi::STATUS_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let r = abi::decode_status_request(exact, memory.len() as u64)
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let object = copy32_bounded(memory, r.object_identity)?;
            let object = &object[..r.object_identity.length() as usize];
            if !a.authorize_status(r.scope, object) {
                return Ok(abi::encode_status_response(Err(
                    abi::StatusError::PermissionDenied,
                )));
            }
            let output = write(memory, r.output)?;
            let result = p.status(r.scope, object, output);
            finish_status(result, output)
        }
        abi::OP_ACCOUNT_OPERATION => {
            let exact: &[u8; abi::ACCOUNT_OPERATION_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let r = abi::decode_account_operation_request(exact, memory.len() as u64)
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let request = copy4096(memory, r.request)?;
            let request = &request[..r.request.length() as usize];
            if !a.authorize_account(r.operation, r.policy_generation, request) {
                return Ok(abi::encode_account_operation_response(Err(
                    abi::AccountOperationError::PermissionDenied,
                )));
            }
            let output = write(memory, r.output)?;
            let result = p.account_operation(r.operation, r.policy_generation, request, output);
            finish_account(result, output)
        }
        abi::OP_IDENTITY_OPERATION => {
            let exact: &[u8; abi::IDENTITY_OPERATION_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let r = abi::decode_identity_operation_request(exact, memory.len() as u64)
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let identity = copy16(memory, r.identity)?;
            let identity = &identity[..r.identity.length() as usize];
            let request = copy8192(memory, r.request)?;
            let request = &request[..r.request.length() as usize];
            if !a.authorize_identity(r.operation, identity, r.policy_generation, request) {
                return Ok(abi::encode_identity_operation_response(Err(
                    abi::IdentityOperationError::PermissionDenied,
                )));
            }
            let output = write(memory, r.output)?;
            let result =
                p.identity_operation(r.operation, identity, r.policy_generation, request, output);
            finish_identity(result, output)
        }
        abi::OP_BACKUP_OPERATION => {
            let exact: &[u8; abi::BACKUP_OPERATION_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let r = abi::decode_backup_operation_request(exact, memory.len() as u64)
                .map_err(|_| LifecycleDispatchError::InvalidFrame)?;
            let request = copy4096(memory, r.request)?;
            let request = &request[..r.request.length() as usize];
            if !a.authorize_backup(r.operation, r.policy_generation, request) {
                return Ok(abi::encode_backup_operation_response(Err(
                    abi::BackupOperationError::PermissionDenied,
                )));
            }
            let output = write(memory, r.output)?;
            let result = p.backup_operation(r.operation, r.policy_generation, request, output);
            finish_backup(result, output)
        }
        _ => Err(LifecycleDispatchError::InvalidFrame),
    }
}
fn finish_status(
    r: Result<abi::StatusResponse, abi::StatusError>,
    o: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], LifecycleDispatchError> {
    let r = sanitize(r, o, 8192, |v| v.written, abi::StatusError::InvalidRequest);
    Ok(abi::encode_status_response(r))
}
fn finish_account(
    r: Result<abi::AccountOperationResponse, abi::AccountOperationError>,
    o: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], LifecycleDispatchError> {
    let r = sanitize(
        r,
        o,
        4096,
        |v| v.written,
        abi::AccountOperationError::OperationFailed,
    );
    Ok(abi::encode_account_operation_response(r))
}
fn finish_identity(
    r: Result<abi::IdentityOperationResponse, abi::IdentityOperationError>,
    o: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], LifecycleDispatchError> {
    let r = sanitize(
        r,
        o,
        8192,
        |v| v.written,
        abi::IdentityOperationError::OperationFailed,
    );
    Ok(abi::encode_identity_operation_response(r))
}
fn finish_backup(
    r: Result<abi::BackupOperationResponse, abi::BackupOperationError>,
    o: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], LifecycleDispatchError> {
    let r = sanitize(
        r,
        o,
        8192,
        |v| v.written,
        abi::BackupOperationError::OperationFailed,
    );
    Ok(abi::encode_backup_operation_response(r))
}
fn sanitize<T, E: Copy, F: FnOnce(&T) -> u64>(
    r: Result<T, E>,
    o: &mut [u8],
    max: u64,
    written: F,
    fallback: E,
) -> Result<T, E>
where
    T: Generation,
{
    match r {
        Ok(v)
            if {
                let w = written(&v);
                w != 0 && w <= o.len() as u64 && w <= max && v.generation() != 0
            } =>
        {
            Ok(v)
        }
        Ok(_) => {
            o.fill(0);
            Err(fallback)
        }
        Err(e) => {
            o.fill(0);
            Err(e)
        }
    }
}
trait Generation {
    fn generation(&self) -> u64;
}
impl Generation for abi::StatusResponse {
    fn generation(&self) -> u64 {
        self.state_generation
    }
}
impl Generation for abi::AccountOperationResponse {
    fn generation(&self) -> u64 {
        self.account_generation
    }
}
impl Generation for abi::IdentityOperationResponse {
    fn generation(&self) -> u64 {
        self.identity_generation
    }
}
impl Generation for abi::BackupOperationResponse {
    fn generation(&self) -> u64 {
        self.backup_generation
    }
}
fn operation(f: &[u8]) -> Result<u32, LifecycleDispatchError> {
    let b = f.get(52..56).ok_or(LifecycleDispatchError::InvalidFrame)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}
fn bounds(o: u64, l: u64, total: usize) -> Result<(usize, usize), LifecycleDispatchError> {
    let s = usize::try_from(o).map_err(|_| LifecycleDispatchError::InvalidFrame)?;
    let l = usize::try_from(l).map_err(|_| LifecycleDispatchError::InvalidFrame)?;
    let e = s
        .checked_add(l)
        .ok_or(LifecycleDispatchError::InvalidFrame)?;
    if e > total {
        Err(LifecycleDispatchError::InvalidFrame)
    } else {
        Ok((s, e))
    }
}
fn read(m: &[u8], v: abi::BorrowedReadView) -> Result<&[u8], LifecycleDispatchError> {
    let (s, e) = bounds(v.offset(), v.length(), m.len())?;
    m.get(s..e).ok_or(LifecycleDispatchError::InvalidFrame)
}
fn write(m: &mut [u8], v: abi::BorrowedWriteView) -> Result<&mut [u8], LifecycleDispatchError> {
    let total = m.len();
    let (s, e) = bounds(v.offset(), v.length(), total)?;
    m.get_mut(s..e).ok_or(LifecycleDispatchError::InvalidFrame)
}
fn copy16(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 16], LifecycleDispatchError> {
    copy(m, v)
}
fn copy32_bounded(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 32], LifecycleDispatchError> {
    copy(m, v)
}
fn copy4096(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 4096], LifecycleDispatchError> {
    copy(m, v)
}
fn copy8192(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 8192], LifecycleDispatchError> {
    copy(m, v)
}
fn copy<const N: usize>(
    m: &[u8],
    v: abi::BorrowedReadView,
) -> Result<[u8; N], LifecycleDispatchError> {
    let source = read(m, v)?;
    let mut out = [0; N];
    out.get_mut(..source.len())
        .ok_or(LifecycleDispatchError::InvalidFrame)?
        .copy_from_slice(source);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Authorizer(bool);
    impl CertificateLifecycleAuthorizer for Authorizer {
        fn authorize_status(&self, _: u32, _: &[u8]) -> bool {
            self.0
        }
        fn authorize_account(&self, _: u32, _: u64, _: &[u8]) -> bool {
            self.0
        }
        fn authorize_identity(&self, _: u32, _: &[u8], _: u64, _: &[u8]) -> bool {
            self.0
        }
        fn authorize_backup(&self, _: u32, _: u64, _: &[u8]) -> bool {
            self.0
        }
    }
    struct Provider {
        calls: u32,
    }
    impl CertificateLifecycleProvider for Provider {
        fn status(
            &mut self,
            _: u32,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            self.calls += 1;
            unreachable!()
        }
        fn account_operation(
            &mut self,
            operation: u32,
            _: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            self.calls += 1;
            assert_eq!(operation, abi::ACCOUNT_ROLLOVER);
            assert_eq!(request, b"exact");
            output[..2].copy_from_slice(b"ok");
            Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 9,
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
    fn authorization_precedes_provider_and_exact_request_is_copied() {
        let mut memory = [0u8; 256];
        memory[..5].copy_from_slice(b"exact");
        let r = abi::AccountOperationRequest {
            operation: abi::ACCOUNT_ROLLOVER,
            policy_generation: 7,
            request: abi::BorrowedReadView::within(0, 5, 256).unwrap(),
            output: abi::BorrowedWriteView::within(32, 64, 256).unwrap(),
        };
        let frame = abi::encode_account_operation_request(r).unwrap();
        let mut provider = Provider { calls: 0 };
        let denied =
            dispatch_lifecycle_call(&Authorizer(false), &mut provider, &frame, &mut memory)
                .unwrap();
        assert_eq!(
            abi::decode_account_operation_response(&denied, 64),
            Ok(Err(abi::AccountOperationError::PermissionDenied))
        );
        assert_eq!(provider.calls, 0);
        let allowed =
            dispatch_lifecycle_call(&Authorizer(true), &mut provider, &frame, &mut memory).unwrap();
        assert_eq!(
            abi::decode_account_operation_response(&allowed, 64),
            Ok(Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 9
            }))
        );
        assert_eq!(&memory[32..34], b"ok");
        assert_eq!(provider.calls, 1);
    }
}
