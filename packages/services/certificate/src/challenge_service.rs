use mrml_interface_certificate_challenge_v1 as abi;

pub struct PreparedChallenge<'a> {
    pub kind: u32,
    pub generation: u64,
    pub order_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub identifier: &'a [u8],
    pub token: &'a [u8],
    pub key_authorization_digest: [u8; 32],
    pub not_before: u64,
    pub expires: u64,
    pub policy_generation: u64,
}
pub trait CertificateChallengeProvider {
    fn prepare(
        &mut self,
        request: PreparedChallenge<'_>,
        output: &mut [u8],
    ) -> Result<abi::PrepareResponse, abi::PrepareError>;
    fn activate(&mut self, receipt: &[u8]) -> Result<abi::ActivateResponse, abi::ActivateError>;
    fn prepare_removal(
        &mut self,
        receipt: &[u8],
    ) -> Result<abi::PrepareRemovalResponse, abi::PrepareRemovalError>;
    fn commit_removal(
        &mut self,
        receipt: &[u8],
    ) -> Result<abi::CommitRemovalResponse, abi::CommitRemovalError>;
    fn authoritative_state(
        &mut self,
        receipt: &[u8],
    ) -> Result<abi::AuthoritativeStateResponse, abi::AuthoritativeStateError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeDispatchError {
    InvalidFrame,
}
pub fn dispatch_challenge_call<P: CertificateChallengeProvider>(
    p: &mut P,
    frame: &[u8],
    memory: &mut [u8],
) -> Result<[u8; abi::RESPONSE_BYTES], ChallengeDispatchError> {
    match operation(frame)? {
        abi::OP_PREPARE => {
            let exact: &[u8; abi::PREPARE_REQUEST_BYTES] = frame
                .try_into()
                .map_err(|_| ChallengeDispatchError::InvalidFrame)?;
            let r = abi::decode_prepare_request(exact, memory.len() as u64)
                .map_err(|_| ChallengeDispatchError::InvalidFrame)?;
            let order = copy32(memory, r.order_digest)?;
            let auth = copy32(memory, r.authorization_digest)?;
            let identifier = copy253(memory, r.identifier)?;
            let token = copy128(memory, r.token)?;
            let digest = copy32(memory, r.key_authorization_digest)?;
            let output = write(memory, r.output)?;
            let request = PreparedChallenge {
                kind: r.challenge_kind,
                generation: r.challenge_generation,
                order_digest: order,
                authorization_digest: auth,
                identifier: &identifier[..r.identifier.length() as usize],
                token: &token[..r.token.length() as usize],
                key_authorization_digest: digest,
                not_before: r.not_before,
                expires: r.expires,
                policy_generation: r.policy_generation,
            };
            let result = p.prepare(request, output);
            if result.as_ref().is_ok_and(|v| {
                !valid_written(v.written, output.len(), 128) || v.publisher_generation == 0
            }) {
                output.fill(0);
                return Ok(abi::encode_prepare_response(Err(
                    abi::PrepareError::InvalidRequest,
                )));
            }
            if result.is_err() {
                output.fill(0)
            }
            Ok(abi::encode_prepare_response(result))
        }
        abi::OP_ACTIVATE => {
            let r = decode_receipt(frame, memory, abi::decode_activate_request)?;
            Ok(abi::encode_activate_response(validate_generation(
                p.activate(r),
                abi::ActivateError::PublicationFailed,
            )))
        }
        abi::OP_PREPARE_REMOVAL => {
            let r = decode_receipt(frame, memory, abi::decode_prepare_removal_request)?;
            Ok(abi::encode_prepare_removal_response(validate_generation(
                p.prepare_removal(r),
                abi::PrepareRemovalError::InvalidRequest,
            )))
        }
        abi::OP_COMMIT_REMOVAL => {
            let r = decode_receipt(frame, memory, abi::decode_commit_removal_request)?;
            Ok(abi::encode_commit_removal_response(validate_generation(
                p.commit_removal(r),
                abi::CommitRemovalError::RemovalUncertain,
            )))
        }
        abi::OP_AUTHORITATIVE_STATE => {
            let r = decode_receipt(frame, memory, abi::decode_authoritative_state_request)?;
            let result = match p.authoritative_state(r) {
                Ok(v)
                    if v.publisher_generation != 0
                        && (abi::PUBLICATION_PREPARED..=abi::PUBLICATION_REMOVED)
                            .contains(&v.state) =>
                {
                    Ok(v)
                }
                Ok(_) => Err(abi::AuthoritativeStateError::UnknownReceipt),
                Err(e) => Err(e),
            };
            Ok(abi::encode_authoritative_state_response(result))
        }
        _ => Err(ChallengeDispatchError::InvalidFrame),
    }
}
fn validate_generation<T: Copy, E: Copy>(r: Result<T, E>, fallback: E) -> Result<T, E>
where
    T: Generation,
{
    match r {
        Ok(v) if v.generation() != 0 => Ok(v),
        Ok(_) => Err(fallback),
        Err(e) => Err(e),
    }
}
trait Generation {
    fn generation(self) -> u64;
}
impl Generation for u64 {
    fn generation(self) -> u64 {
        self
    }
}
fn decode_receipt<'a, R, F>(
    frame: &[u8],
    memory: &'a [u8],
    decode: F,
) -> Result<&'a [u8], ChallengeDispatchError>
where
    F: FnOnce(&[u8; abi::RECEIPT_REQUEST_BYTES], u64) -> Result<R, abi::ProtocolError>,
    R: Receipt,
{
    let exact: &[u8; abi::RECEIPT_REQUEST_BYTES] = frame
        .try_into()
        .map_err(|_| ChallengeDispatchError::InvalidFrame)?;
    let r = decode(exact, memory.len() as u64).map_err(|_| ChallengeDispatchError::InvalidFrame)?;
    read(memory, r.receipt())
}
trait Receipt {
    fn receipt(self) -> abi::BorrowedReadView;
}
impl Receipt for abi::ActivateRequest {
    fn receipt(self) -> abi::BorrowedReadView {
        self.receipt
    }
}
impl Receipt for abi::PrepareRemovalRequest {
    fn receipt(self) -> abi::BorrowedReadView {
        self.receipt
    }
}
impl Receipt for abi::CommitRemovalRequest {
    fn receipt(self) -> abi::BorrowedReadView {
        self.receipt
    }
}
impl Receipt for abi::AuthoritativeStateRequest {
    fn receipt(self) -> abi::BorrowedReadView {
        self.receipt
    }
}
fn operation(frame: &[u8]) -> Result<u32, ChallengeDispatchError> {
    let b = frame
        .get(52..56)
        .ok_or(ChallengeDispatchError::InvalidFrame)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}
fn valid_written(w: u64, len: usize, max: u64) -> bool {
    w != 0 && w <= len as u64 && w <= max
}
fn bounds(o: u64, l: u64, total: usize) -> Result<(usize, usize), ChallengeDispatchError> {
    let s = usize::try_from(o).map_err(|_| ChallengeDispatchError::InvalidFrame)?;
    let l = usize::try_from(l).map_err(|_| ChallengeDispatchError::InvalidFrame)?;
    let e = s
        .checked_add(l)
        .ok_or(ChallengeDispatchError::InvalidFrame)?;
    if e > total {
        Err(ChallengeDispatchError::InvalidFrame)
    } else {
        Ok((s, e))
    }
}
fn read(m: &[u8], v: abi::BorrowedReadView) -> Result<&[u8], ChallengeDispatchError> {
    let (s, e) = bounds(v.offset(), v.length(), m.len())?;
    m.get(s..e).ok_or(ChallengeDispatchError::InvalidFrame)
}
fn write(m: &mut [u8], v: abi::BorrowedWriteView) -> Result<&mut [u8], ChallengeDispatchError> {
    let total = m.len();
    let (s, e) = bounds(v.offset(), v.length(), total)?;
    m.get_mut(s..e).ok_or(ChallengeDispatchError::InvalidFrame)
}
fn copy32(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 32], ChallengeDispatchError> {
    read(m, v)?
        .try_into()
        .map_err(|_| ChallengeDispatchError::InvalidFrame)
}
fn copy253(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 253], ChallengeDispatchError> {
    copy_bounded(m, v)
}
fn copy128(m: &[u8], v: abi::BorrowedReadView) -> Result<[u8; 128], ChallengeDispatchError> {
    copy_bounded(m, v)
}
fn copy_bounded<const N: usize>(
    m: &[u8],
    v: abi::BorrowedReadView,
) -> Result<[u8; N], ChallengeDispatchError> {
    let source = read(m, v)?;
    let mut out = [0; N];
    out.get_mut(..source.len())
        .ok_or(ChallengeDispatchError::InvalidFrame)?
        .copy_from_slice(source);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider;
    impl CertificateChallengeProvider for Provider {
        fn prepare(
            &mut self,
            request: PreparedChallenge<'_>,
            output: &mut [u8],
        ) -> Result<abi::PrepareResponse, abi::PrepareError> {
            assert_eq!(request.kind, abi::CHALLENGE_HTTP01);
            output[..4].copy_from_slice(b"rcpt");
            Ok(abi::PrepareResponse {
                written: 4,
                publisher_generation: 9,
            })
        }
        fn activate(&mut self, _: &[u8]) -> Result<u64, abi::ActivateError> {
            Ok(10)
        }
        fn prepare_removal(&mut self, _: &[u8]) -> Result<u64, abi::PrepareRemovalError> {
            Ok(11)
        }
        fn commit_removal(&mut self, _: &[u8]) -> Result<u64, abi::CommitRemovalError> {
            Ok(12)
        }
        fn authoritative_state(
            &mut self,
            _: &[u8],
        ) -> Result<abi::AuthoritativeStateResponse, abi::AuthoritativeStateError> {
            Ok(abi::AuthoritativeStateResponse {
                state: abi::PUBLICATION_ACTIVE,
                publisher_generation: 10,
            })
        }
    }
    #[test]
    fn dispatch_copies_binding_before_lending_output() {
        let mut memory = [0u8; 512];
        memory[..32].fill(1);
        memory[32..64].fill(2);
        memory[64..75].copy_from_slice(b"git.example");
        memory[75..80].copy_from_slice(b"token");
        memory[80..112].fill(3);
        let r = abi::PrepareRequest {
            challenge_kind: abi::CHALLENGE_HTTP01,
            challenge_generation: 7,
            order_digest: abi::BorrowedReadView::within(0, 32, 512).unwrap(),
            authorization_digest: abi::BorrowedReadView::within(32, 32, 512).unwrap(),
            identifier: abi::BorrowedReadView::within(64, 11, 512).unwrap(),
            token: abi::BorrowedReadView::within(75, 5, 512).unwrap(),
            key_authorization_digest: abi::BorrowedReadView::within(80, 32, 512).unwrap(),
            not_before: 1,
            expires: 9,
            policy_generation: 4,
            output: abi::BorrowedWriteView::within(128, 128, 512).unwrap(),
        };
        let response = dispatch_challenge_call(
            &mut Provider,
            &abi::encode_prepare_request(r).unwrap(),
            &mut memory,
        )
        .unwrap();
        assert_eq!(
            abi::decode_prepare_response(&response, 128),
            Ok(Ok(abi::PrepareResponse {
                written: 4,
                publisher_generation: 9
            }))
        );
        assert_eq!(&memory[128..132], b"rcpt");
    }
}
