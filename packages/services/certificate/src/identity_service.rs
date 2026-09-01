use mrml_interface_certificate_identity_v1 as abi;

pub trait CertificateIdentityProvider {
    fn describe(
        &mut self,
        identity: &[u8],
        observed_generation: u64,
        output: &mut [u8],
    ) -> Result<abi::DescribeResponse, abi::DescribeError>;
    fn read_chain(
        &mut self,
        identity: &[u8],
        generation: u64,
        certificate_index: u32,
        output: &mut [u8],
    ) -> Result<abi::ReadChainResponse, abi::ReadChainError>;
    fn request_signing_route(
        &mut self,
        identity: &[u8],
        generation: u64,
        key_identity: &[u8; 32],
        output: &mut [u8],
    ) -> Result<abi::RequestSigningRouteResponse, abi::RequestSigningRouteError>;
    fn poll_generation(
        &mut self,
        identity: &[u8],
        observed_generation: u64,
    ) -> Result<abi::PollGenerationResponse, abi::PollGenerationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityDispatchError {
    InvalidFrame,
}

pub fn dispatch_identity_call<P: CertificateIdentityProvider>(
    provider: &mut P,
    frame: &[u8],
    memory: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], IdentityDispatchError> {
    let op = operation(frame)?;
    match op {
        abi::OP_DESCRIBE => {
            let exact: &[u8; abi::DESCRIBE_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let r = abi::decode_describe_request(exact, memory.len() as u64)
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let identity = copy_identity(memory, r.identity)?;
            let output = write(memory, r.output)?;
            let result = provider.describe(
                &identity[..r.identity.length() as usize],
                r.observed_generation,
                output,
            );
            if !matches!(&result, Ok(v) if valid_written(v.written, output.len(), 2048) && v.current_generation != 0)
                && result.is_ok()
            {
                output.fill(0);
                return Ok(abi::encode_describe_response(Err(
                    abi::DescribeError::IdentityUnavailable,
                )));
            }
            if result.is_err() {
                output.fill(0)
            }
            Ok(abi::encode_describe_response(result))
        }
        abi::OP_READ_CHAIN => {
            let exact: &[u8; abi::READ_CHAIN_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let r = abi::decode_read_chain_request(exact, memory.len() as u64)
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let identity = copy_identity(memory, r.identity)?;
            let output = write(memory, r.output)?;
            let result = provider.read_chain(
                &identity[..r.identity.length() as usize],
                r.generation,
                r.certificate_index,
                output,
            );
            if !matches!(&result, Ok(v) if valid_written(v.written, output.len(), 16384) && v.certificate_count != 0)
                && result.is_ok()
            {
                output.fill(0);
                return Ok(abi::encode_read_chain_response(Err(
                    abi::ReadChainError::InvalidRequest,
                )));
            }
            if result.is_err() {
                output.fill(0)
            }
            Ok(abi::encode_read_chain_response(result))
        }
        abi::OP_REQUEST_SIGNING_ROUTE => {
            let exact: &[u8; abi::REQUEST_SIGNING_ROUTE_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let r = abi::decode_request_signing_route_request(exact, memory.len() as u64)
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let identity = copy_identity(memory, r.identity)?;
            let key = copy_32(memory, r.key_identity)?;
            let output = write(memory, r.output)?;
            let result = provider.request_signing_route(
                &identity[..r.identity.length() as usize],
                r.generation,
                &key,
                output,
            );
            if !matches!(&result, Ok(v) if valid_written(v.written, output.len(), 64) && v.route_generation != 0)
                && result.is_ok()
            {
                output.fill(0);
                return Ok(abi::encode_request_signing_route_response(Err(
                    abi::RequestSigningRouteError::RouteUnavailable,
                )));
            }
            if result.is_err() {
                output.fill(0)
            }
            Ok(abi::encode_request_signing_route_response(result))
        }
        abi::OP_POLL_GENERATION => {
            let exact: &[u8; abi::POLL_GENERATION_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let r = abi::decode_poll_generation_request(exact, memory.len() as u64)
                .map_err(|_| IdentityDispatchError::InvalidFrame)?;
            let identity = copy_identity(memory, r.identity)?;
            let result = provider.poll_generation(
                &identity[..r.identity.length() as usize],
                r.observed_generation,
            );
            let result = match result {
                Ok(v)
                    if v.current_generation != 0
                        && (abi::HEALTH_HEALTHY..=abi::HEALTH_EXPIRED).contains(&v.health) =>
                {
                    Ok(v)
                }
                Ok(_) => Err(abi::PollGenerationError::IdentityUnavailable),
                Err(error) => Err(error),
            };
            Ok(abi::encode_poll_generation_response(result))
        }
        _ => Err(IdentityDispatchError::InvalidFrame),
    }
}

fn operation(frame: &[u8]) -> Result<u32, IdentityDispatchError> {
    let bytes = frame
        .get(52..56)
        .ok_or(IdentityDispatchError::InvalidFrame)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}
fn valid_written(written: u64, len: usize, max: u64) -> bool {
    written != 0 && written <= len as u64 && written <= max
}
fn bounds(offset: u64, length: u64, total: usize) -> Result<(usize, usize), IdentityDispatchError> {
    let start = usize::try_from(offset).map_err(|_| IdentityDispatchError::InvalidFrame)?;
    let len = usize::try_from(length).map_err(|_| IdentityDispatchError::InvalidFrame)?;
    let end = start
        .checked_add(len)
        .ok_or(IdentityDispatchError::InvalidFrame)?;
    if end > total {
        Err(IdentityDispatchError::InvalidFrame)
    } else {
        Ok((start, end))
    }
}
fn read(memory: &[u8], view: abi::BorrowedReadView) -> Result<&[u8], IdentityDispatchError> {
    let (s, e) = bounds(view.offset(), view.length(), memory.len())?;
    memory.get(s..e).ok_or(IdentityDispatchError::InvalidFrame)
}
fn write(
    memory: &mut [u8],
    view: abi::BorrowedWriteView,
) -> Result<&mut [u8], IdentityDispatchError> {
    let total = memory.len();
    let (s, e) = bounds(view.offset(), view.length(), total)?;
    memory
        .get_mut(s..e)
        .ok_or(IdentityDispatchError::InvalidFrame)
}
fn copy_identity(
    memory: &[u8],
    view: abi::BorrowedReadView,
) -> Result<[u8; 16], IdentityDispatchError> {
    let source = read(memory, view)?;
    let mut result = [0; 16];
    result
        .get_mut(..source.len())
        .ok_or(IdentityDispatchError::InvalidFrame)?
        .copy_from_slice(source);
    Ok(result)
}
fn copy_32(memory: &[u8], view: abi::BorrowedReadView) -> Result<[u8; 32], IdentityDispatchError> {
    read(memory, view)?
        .try_into()
        .map_err(|_| IdentityDispatchError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider;
    impl CertificateIdentityProvider for Provider {
        fn describe(
            &mut self,
            _: &[u8],
            _: u64,
            o: &mut [u8],
        ) -> Result<abi::DescribeResponse, abi::DescribeError> {
            o[..3].copy_from_slice(b"id1");
            Ok(abi::DescribeResponse {
                written: 3,
                current_generation: 4,
            })
        }
        fn read_chain(
            &mut self,
            _: &[u8],
            _: u64,
            _: u32,
            _: &mut [u8],
        ) -> Result<abi::ReadChainResponse, abi::ReadChainError> {
            Err(abi::ReadChainError::StaleIdentity)
        }
        fn request_signing_route(
            &mut self,
            _: &[u8],
            _: u64,
            _: &[u8; 32],
            _: &mut [u8],
        ) -> Result<abi::RequestSigningRouteResponse, abi::RequestSigningRouteError> {
            Err(abi::RequestSigningRouteError::PermissionDenied)
        }
        fn poll_generation(
            &mut self,
            _: &[u8],
            _: u64,
        ) -> Result<abi::PollGenerationResponse, abi::PollGenerationError> {
            Ok(abi::PollGenerationResponse {
                current_generation: 4,
                health: abi::HEALTH_HEALTHY,
            })
        }
    }
    #[test]
    fn dispatches_exact_operation_and_zeros_failed_output() {
        let mut memory = [0u8; 256];
        memory[..16].copy_from_slice(&[1; 16]);
        let r = abi::DescribeRequest {
            identity: abi::BorrowedReadView::within(0, 16, 256).unwrap(),
            observed_generation: 3,
            output: abi::BorrowedWriteView::within(32, 32, 256).unwrap(),
        };
        let response = dispatch_identity_call(
            &mut Provider,
            &abi::encode_describe_request(r).unwrap(),
            &mut memory,
        )
        .unwrap();
        assert_eq!(
            abi::decode_describe_response(&response, 32),
            Ok(Ok(abi::DescribeResponse {
                written: 3,
                current_generation: 4
            }))
        );
        assert_eq!(&memory[32..35], b"id1");
    }
}
