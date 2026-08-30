use crate::arch::x86_64::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::{
    Capability, MAX_CAPABILITIES, MAX_INLINE_PAYLOAD, ObjectId, ReceiveTimeout, Rights, TaskId,
};

pub const X86_USER_CALL_VECTOR: u8 = 0x80;
pub const MAX_SYSCALL_INLINE_PAYLOAD: usize = 24;
pub const MAX_SHARED_BUFFER_SYSCALL_BYTES: usize = 1024 * 1024;
pub const CAPABILITY_TRANSFER_DESCRIPTOR_BYTES: usize = 16;
pub const RECEIVED_CAPABILITY_TOKEN_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum SyscallCompletionStatus {
    Success = 0,
    Error = 1,
    TimedOut = 2,
}

impl SyscallCompletionStatus {
    pub const fn code(self) -> u64 {
        self as u64
    }
}
const USER_RETURN_FLAGS: u64 = 2
    | (1 << 0)
    | (1 << 2)
    | (1 << 4)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 18)
    | (1 << 21);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallError {
    UnknownOperation,
    ReservedArgument,
    InvalidCapability,
    InvalidObject,
    InvalidRights,
    InvalidPolicy,
    InvalidTimeout,
    InvalidTask,
    PayloadTooLarge,
    TooManyCapabilities,
    InvalidBuffer,
    InvalidPrivilege,
    InvalidInstruction,
    InvalidStack,
    InvalidFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserReturnError {
    InvalidPrivilege,
    InvalidInstruction,
    InvalidStack,
    InvalidFlags,
}

impl From<UserReturnError> for SyscallError {
    fn from(error: UserReturnError) -> Self {
        match error {
            UserReturnError::InvalidPrivilege => Self::InvalidPrivilege,
            UserReturnError::InvalidInstruction => Self::InvalidInstruction,
            UserReturnError::InvalidStack => Self::InvalidStack,
            UserReturnError::InvalidFlags => Self::InvalidFlags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserCallDecodeError {
    Return(UserReturnError),
    Request(SyscallError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityTransferDescriptor {
    pub capability: Capability,
    pub rights: Rights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferCompletion {
    payload_length: u16,
    capability_count: u8,
}

impl BufferCompletion {
    pub fn new(
        payload_length: usize,
        capability_count: usize,
        payload_capacity: usize,
        capability_capacity: usize,
    ) -> Result<Self, SyscallError> {
        if payload_length > payload_capacity
            || payload_length > MAX_INLINE_PAYLOAD
            || capability_count > capability_capacity
            || capability_count > MAX_CAPABILITIES
        {
            return Err(SyscallError::InvalidBuffer);
        }
        Ok(Self {
            payload_length: payload_length as u16,
            capability_count: capability_count as u8,
        })
    }

    pub const fn payload_length(self) -> u16 {
        self.payload_length
    }
    pub const fn capability_count(self) -> u8 {
        self.capability_count
    }
}

pub fn decode_capability_transfers(
    input: &[u8],
    count: usize,
    output: &mut [Option<CapabilityTransferDescriptor>; MAX_CAPABILITIES],
) -> Result<(), SyscallError> {
    if count > MAX_CAPABILITIES
        || input.len()
            != count
                .checked_mul(CAPABILITY_TRANSFER_DESCRIPTOR_BYTES)
                .ok_or(SyscallError::InvalidBuffer)?
    {
        return Err(SyscallError::InvalidBuffer);
    }
    let (chunks, remainder) = input.as_chunks::<CAPABILITY_TRANSFER_DESCRIPTOR_BYTES>();
    if !remainder.is_empty() {
        return Err(SyscallError::InvalidBuffer);
    }
    let mut decoded = [None; MAX_CAPABILITIES];
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk[10..].iter().any(|byte| *byte != 0) {
            return Err(SyscallError::ReservedArgument);
        }
        let token = u64::from_le_bytes(chunk[..8].try_into().expect("fixed descriptor token"));
        if token == 0 || token >> 32 == 0 {
            return Err(SyscallError::InvalidCapability);
        }
        let rights = Rights::from_bits(u16::from_le_bytes([chunk[8], chunk[9]]))
            .map_err(|_| SyscallError::InvalidCapability)?;
        decoded[index] = Some(CapabilityTransferDescriptor {
            capability: Capability::from_token(token),
            rights,
        });
    }
    *output = decoded;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UserCallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl UserCallFrame {
    pub fn validate_return(&self) -> Result<(), UserReturnError> {
        if self.cs != u64::from(USER_CODE_SELECTOR) || self.ss != u64::from(USER_DATA_SELECTOR) {
            return Err(UserReturnError::InvalidPrivilege);
        }
        if !user_address(self.rip) {
            return Err(UserReturnError::InvalidInstruction);
        }
        if !user_address(self.rsp) {
            return Err(UserReturnError::InvalidStack);
        }
        if self.rflags & 2 == 0 || self.rflags & !USER_RETURN_FLAGS != 0 {
            return Err(UserReturnError::InvalidFlags);
        }
        Ok(())
    }

    pub fn request(&self) -> Result<SyscallRequest, SyscallError> {
        self.decode_request().map_err(|error| match error {
            UserCallDecodeError::Return(error) => SyscallError::from(error),
            UserCallDecodeError::Request(error) => error,
        })
    }

    pub fn decode_request(&self) -> Result<SyscallRequest, UserCallDecodeError> {
        self.validate_return()
            .map_err(UserCallDecodeError::Return)?;
        SyscallRequest::decode(
            self.rax, self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9,
        )
        .map_err(UserCallDecodeError::Request)
    }

    pub fn complete(&mut self, sequence: u64) {
        self.rax = 0;
        self.rdx = sequence;
    }

    pub fn complete_message(&mut self, payload: &[u8]) {
        let mut words = [0u64; 3];
        for (index, byte) in payload.iter().take(MAX_SYSCALL_INLINE_PAYLOAD).enumerate() {
            words[index / 8] |= u64::from(*byte) << ((index % 8) * 8);
        }
        self.rax = 0;
        self.rdx = payload.len().min(MAX_SYSCALL_INLINE_PAYLOAD) as u64;
        self.r10 = words[0];
        self.r8 = words[1];
        self.r9 = words[2];
    }

    pub fn complete_buffer(&mut self, completion: BufferCompletion) {
        self.rax = 0;
        self.rdx = u64::from(completion.payload_length());
        self.r10 = u64::from(completion.capability_count());
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_authorization(&mut self, authorized: bool) {
        self.rax = u64::from(!authorized);
        self.rdx = 0;
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_error(&mut self) {
        self.rax = SyscallCompletionStatus::Error.code();
        self.rdx = 0;
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_timeout(&mut self) {
        self.rax = SyscallCompletionStatus::TimedOut.code();
        self.rdx = 0;
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_service_state(&mut self, state: Option<crate::ServiceState>) {
        self.rax = u64::from(state.is_none());
        self.rdx = match state {
            Some(crate::ServiceState::Running) => 1,
            Some(crate::ServiceState::Exited) => 2,
            Some(crate::ServiceState::Faulted) => 3,
            None => 0,
        };
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_service_restart(&mut self, replacement: Option<crate::ServiceId>) {
        self.rax = u64::from(replacement.is_none());
        self.rdx = replacement.map_or(0, crate::ServiceId::token);
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }

    pub fn complete_policy_replacement(&mut self, replaced: bool) {
        self.rax = u64::from(!replaced);
        self.rdx = 0;
        self.r10 = 0;
        self.r8 = 0;
        self.r9 = 0;
    }
}

const fn user_address(address: u64) -> bool {
    address != 0 && address < 1 << 47
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallRequest {
    Yield,
    Receive,
    ReceiveFor {
        timeout: ReceiveTimeout,
    },
    Exit,
    SendInline {
        endpoint: Capability,
        receiver: TaskId,
        payload: [u8; MAX_SYSCALL_INLINE_PAYLOAD],
        length: u8,
    },
    SendBuffer {
        endpoint: Capability,
        receiver: TaskId,
        payload_address: u64,
        payload_length: u16,
        capabilities_address: u64,
        capability_count: u8,
    },
    ReceiveBuffer {
        payload_address: u64,
        payload_capacity: u16,
        capabilities_address: u64,
        capability_capacity: u8,
    },
    AuthorizeCapability {
        capability: Capability,
        object: ObjectId,
        rights: Rights,
    },
    ReadSharedBuffer {
        capability: Capability,
        offset: u64,
        output_address: u64,
        length: u32,
    },
    WriteSharedBuffer {
        capability: Capability,
        offset: u64,
        input_address: u64,
        length: u32,
    },
    QueryService {
        capability: Capability,
        service: crate::ServiceId,
    },
    RestartService {
        capability: Capability,
        service: crate::ServiceId,
    },
    ReplaceServicePolicy {
        capability: Capability,
        service: crate::ServiceId,
        policy: crate::RestartPolicy,
    },
    ReleaseCapability {
        capability: Capability,
    },
}

impl SyscallRequest {
    /// Decodes the pointer-free MRML register ABI. No user address is ever
    /// dereferenced: up to 24 payload bytes travel by value in r10/r8/r9.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        operation: u64,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> Result<Self, SyscallError> {
        match operation {
            0 => {
                if rdi | rsi | rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::Yield)
            }
            1 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 || rsi >> 32 == 0 {
                    return Err(SyscallError::InvalidTask);
                }
                let length = usize::try_from(rdx).map_err(|_| SyscallError::PayloadTooLarge)?;
                if length > MAX_SYSCALL_INLINE_PAYLOAD {
                    return Err(SyscallError::PayloadTooLarge);
                }
                let mut payload = [0u8; MAX_SYSCALL_INLINE_PAYLOAD];
                payload[..8].copy_from_slice(&r10.to_le_bytes());
                payload[8..16].copy_from_slice(&r8.to_le_bytes());
                payload[16..24].copy_from_slice(&r9.to_le_bytes());
                payload[length..].fill(0);
                Ok(Self::SendInline {
                    endpoint: Capability::from_token(rdi),
                    receiver: TaskId::from_token(rsi),
                    payload,
                    length: length as u8,
                })
            }
            2 => {
                if rdi | rsi | rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::Receive)
            }
            3 => {
                if rdi | rsi | rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::Exit)
            }
            4 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 || rsi >> 32 == 0 {
                    return Err(SyscallError::InvalidTask);
                }
                let payload_length =
                    usize::try_from(r10).map_err(|_| SyscallError::PayloadTooLarge)?;
                if payload_length == 0 || payload_length > MAX_INLINE_PAYLOAD {
                    return Err(SyscallError::PayloadTooLarge);
                }
                let capability_count =
                    usize::try_from(r9).map_err(|_| SyscallError::TooManyCapabilities)?;
                if capability_count > MAX_CAPABILITIES {
                    return Err(SyscallError::TooManyCapabilities);
                }
                validate_user_range(rdx, payload_length, MAX_INLINE_PAYLOAD)?;
                let capability_bytes = validate_optional_capability_buffer(
                    r8,
                    capability_count,
                    CAPABILITY_TRANSFER_DESCRIPTOR_BYTES,
                )?;
                validate_disjoint_user_ranges(rdx, payload_length, r8, capability_bytes)?;
                Ok(Self::SendBuffer {
                    endpoint: Capability::from_token(rdi),
                    receiver: TaskId::from_token(rsi),
                    payload_address: rdx,
                    payload_length: payload_length as u16,
                    capabilities_address: r8,
                    capability_count: capability_count as u8,
                })
            }
            5 => {
                let payload_capacity =
                    usize::try_from(rsi).map_err(|_| SyscallError::PayloadTooLarge)?;
                if payload_capacity == 0 || payload_capacity > MAX_INLINE_PAYLOAD {
                    return Err(SyscallError::PayloadTooLarge);
                }
                let capability_capacity =
                    usize::try_from(r10).map_err(|_| SyscallError::TooManyCapabilities)?;
                if capability_capacity > MAX_CAPABILITIES {
                    return Err(SyscallError::TooManyCapabilities);
                }
                if r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                validate_user_range(rdi, payload_capacity, MAX_INLINE_PAYLOAD)?;
                let capability_bytes = validate_optional_capability_buffer(
                    rdx,
                    capability_capacity,
                    RECEIVED_CAPABILITY_TOKEN_BYTES,
                )?;
                validate_disjoint_user_ranges(rdi, payload_capacity, rdx, capability_bytes)?;
                Ok(Self::ReceiveBuffer {
                    payload_address: rdi,
                    payload_capacity: payload_capacity as u16,
                    capabilities_address: rdx,
                    capability_capacity: capability_capacity as u8,
                })
            }
            6 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 {
                    return Err(SyscallError::InvalidObject);
                }
                let bits = u16::try_from(rdx).map_err(|_| SyscallError::InvalidRights)?;
                let rights = Rights::from_bits(bits).map_err(|_| SyscallError::InvalidRights)?;
                if r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::AuthorizeCapability {
                    capability: Capability::from_token(rdi),
                    object: ObjectId(rsi),
                    rights,
                })
            }
            7 | 8 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                let length = usize::try_from(r10).map_err(|_| SyscallError::InvalidBuffer)?;
                validate_user_range(rdx, length, MAX_SHARED_BUFFER_SYSCALL_BYTES)?;
                rsi.checked_add(r10).ok_or(SyscallError::InvalidBuffer)?;
                let capability = Capability::from_token(rdi);
                if operation == 7 {
                    Ok(Self::ReadSharedBuffer {
                        capability,
                        offset: rsi,
                        output_address: rdx,
                        length: length as u32,
                    })
                } else {
                    Ok(Self::WriteSharedBuffer {
                        capability,
                        offset: rsi,
                        input_address: rdx,
                        length: length as u32,
                    })
                }
            }
            9 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 || rsi >> 32 == 0 {
                    return Err(SyscallError::InvalidObject);
                }
                if rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::QueryService {
                    capability: Capability::from_token(rdi),
                    service: crate::ServiceId::from_token(rsi),
                })
            }
            10 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 || rsi >> 32 == 0 {
                    return Err(SyscallError::InvalidObject);
                }
                if rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::RestartService {
                    capability: Capability::from_token(rdi),
                    service: crate::ServiceId::from_token(rsi),
                })
            }
            11 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi == 0 || rsi >> 32 == 0 {
                    return Err(SyscallError::InvalidObject);
                }
                if r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                let maximum_restarts =
                    u32::try_from(rdx).map_err(|_| SyscallError::InvalidPolicy)?;
                let policy = crate::RestartPolicy::new(maximum_restarts, r10, r8)
                    .map_err(|_| SyscallError::InvalidPolicy)?;
                Ok(Self::ReplaceServicePolicy {
                    capability: Capability::from_token(rdi),
                    service: crate::ServiceId::from_token(rsi),
                    policy,
                })
            }
            12 => {
                if rdi == 0 || rdi >> 32 == 0 {
                    return Err(SyscallError::InvalidCapability);
                }
                if rsi | rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                Ok(Self::ReleaseCapability {
                    capability: Capability::from_token(rdi),
                })
            }
            13 => {
                if rsi | rdx | r10 | r8 | r9 != 0 {
                    return Err(SyscallError::ReservedArgument);
                }
                let timeout = ReceiveTimeout::new(rdi).ok_or(SyscallError::InvalidTimeout)?;
                Ok(Self::ReceiveFor { timeout })
            }
            _ => Err(SyscallError::UnknownOperation),
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Yield
            | Self::Receive
            | Self::ReceiveFor { .. }
            | Self::Exit
            | Self::SendBuffer { .. }
            | Self::ReceiveBuffer { .. }
            | Self::AuthorizeCapability { .. }
            | Self::ReadSharedBuffer { .. }
            | Self::WriteSharedBuffer { .. }
            | Self::QueryService { .. }
            | Self::RestartService { .. }
            | Self::ReplaceServicePolicy { .. }
            | Self::ReleaseCapability { .. } => &[],
            Self::SendInline {
                payload, length, ..
            } => &payload[..usize::from(*length)],
        }
    }
}

fn validate_user_range(address: u64, length: usize, maximum: usize) -> Result<(), SyscallError> {
    if length == 0 || length > maximum {
        return Err(SyscallError::InvalidBuffer);
    }
    validate_buffer_address(address, 1)?;
    let length = u64::try_from(length).map_err(|_| SyscallError::InvalidBuffer)?;
    let end = address
        .checked_add(length)
        .ok_or(SyscallError::InvalidBuffer)?;
    if end > 1 << 47 {
        return Err(SyscallError::InvalidBuffer);
    }
    Ok(())
}

fn validate_buffer_address(address: u64, alignment: u64) -> Result<(), SyscallError> {
    if address == 0 || address >= 1 << 47 || !address.is_multiple_of(alignment) {
        return Err(SyscallError::InvalidBuffer);
    }
    Ok(())
}

fn validate_optional_capability_buffer(
    address: u64,
    capability_count: usize,
    entry_bytes: usize,
) -> Result<usize, SyscallError> {
    if capability_count == 0 {
        if address != 0 {
            return Err(SyscallError::ReservedArgument);
        }
        return Ok(0);
    }
    let length = capability_count
        .checked_mul(entry_bytes)
        .ok_or(SyscallError::InvalidBuffer)?;
    validate_user_range(
        address,
        length,
        MAX_CAPABILITIES * CAPABILITY_TRANSFER_DESCRIPTOR_BYTES,
    )?;
    if !address.is_multiple_of(RECEIVED_CAPABILITY_TOKEN_BYTES as u64) {
        return Err(SyscallError::InvalidBuffer);
    }
    Ok(length)
}

fn validate_disjoint_user_ranges(
    first_address: u64,
    first_length: usize,
    second_address: u64,
    second_length: usize,
) -> Result<(), SyscallError> {
    if first_length == 0 || second_length == 0 {
        return Ok(());
    }
    let first_end = first_address
        .checked_add(u64::try_from(first_length).map_err(|_| SyscallError::InvalidBuffer)?)
        .ok_or(SyscallError::InvalidBuffer)?;
    let second_end = second_address
        .checked_add(u64::try_from(second_length).map_err(|_| SyscallError::InvalidBuffer)?)
        .ok_or(SyscallError::InvalidBuffer)?;
    if first_address < second_end && second_address < first_end {
        return Err(SyscallError::InvalidBuffer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yield_requires_every_reserved_register_to_be_zero() {
        assert_eq!(
            SyscallRequest::decode(0, 0, 0, 0, 0, 0, 0),
            Ok(SyscallRequest::Yield)
        );
        assert_eq!(
            SyscallRequest::decode(0, 0, 0, 0, 1, 0, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn receive_requires_reserved_registers_to_be_zero() {
        assert_eq!(
            SyscallRequest::decode(2, 0, 0, 0, 0, 0, 0),
            Ok(SyscallRequest::Receive)
        );
        assert_eq!(
            SyscallRequest::decode(2, 0, 1, 0, 0, 0, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn relative_timeout_receive_is_nonzero_and_register_bounded() {
        assert_eq!(
            SyscallRequest::decode(13, 7, 0, 0, 0, 0, 0),
            Ok(SyscallRequest::ReceiveFor {
                timeout: ReceiveTimeout::new(7).unwrap()
            })
        );
        assert_eq!(
            SyscallRequest::decode(13, 0, 0, 0, 0, 0, 0),
            Err(SyscallError::InvalidTimeout)
        );
        for arguments in [
            [7, 1, 0, 0, 0, 0],
            [7, 0, 1, 0, 0, 0],
            [7, 0, 0, 1, 0, 0],
            [7, 0, 0, 0, 1, 0],
            [7, 0, 0, 0, 0, 1],
        ] {
            assert_eq!(
                SyscallRequest::decode(
                    13,
                    arguments[0],
                    arguments[1],
                    arguments[2],
                    arguments[3],
                    arguments[4],
                    arguments[5],
                ),
                Err(SyscallError::ReservedArgument)
            );
        }
    }

    #[test]
    fn exit_requires_every_reserved_register_to_be_zero() {
        assert_eq!(
            SyscallRequest::decode(3, 0, 0, 0, 0, 0, 0),
            Ok(SyscallRequest::Exit)
        );
        assert_eq!(
            SyscallRequest::decode(3, 0, 0, 0, 0, 1, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn message_completion_is_pointer_free_and_zero_padded() {
        let mut frame = valid_yield_frame();
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_message(b"ping");
        assert_eq!(frame.rax, 0);
        assert_eq!(frame.rdx, 4);
        assert_eq!(frame.r10, u64::from_le_bytes(*b"ping\0\0\0\0"));
        assert_eq!(frame.r8, 0);
        assert_eq!(frame.r9, 0);
    }

    #[test]
    fn buffer_completion_returns_only_bounded_result_counts() {
        let mut frame = valid_yield_frame();
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_buffer(BufferCompletion::new(368, 5, 368, 5).unwrap());
        assert_eq!(frame.rax, 0);
        assert_eq!(frame.rdx, 368);
        assert_eq!(frame.r10, 5);
        assert_eq!(frame.r8, 0);
        assert_eq!(frame.r9, 0);
    }

    #[test]
    fn buffer_completion_requires_exact_receive_capacities() {
        assert_eq!(
            BufferCompletion::new(112, 1, 112, 1)
                .unwrap()
                .payload_length(),
            112
        );
        assert_eq!(
            BufferCompletion::new(113, 1, 112, 1),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            BufferCompletion::new(112, 2, 112, 1),
            Err(SyscallError::InvalidBuffer)
        );
    }

    #[test]
    fn authorization_completion_is_detail_free() {
        let mut frame = valid_yield_frame();
        frame.rdx = u64::MAX;
        frame.r10 = u64::MAX;
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_authorization(false);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (1, 0, 0, 0, 0)
        );
        frame.complete_authorization(true);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn generic_error_completion_is_detail_free() {
        let mut frame = valid_yield_frame();
        frame.rdx = u64::MAX;
        frame.r10 = u64::MAX;
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_error();
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (1, 0, 0, 0, 0)
        );
        frame.rdx = u64::MAX;
        frame.r10 = u64::MAX;
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_timeout();
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (SyscallCompletionStatus::TimedOut.code(), 0, 0, 0, 0)
        );
        assert_ne!(
            SyscallCompletionStatus::TimedOut.code(),
            SyscallCompletionStatus::Error.code()
        );
    }

    #[test]
    fn inline_send_is_pointer_free_canonical_and_bounded() {
        let endpoint = (7u64 << 32) | 3;
        let receiver = (9u64 << 32) | 2;
        let request = SyscallRequest::decode(
            1,
            endpoint,
            receiver,
            11,
            u64::from_le_bytes(*b"hello wo"),
            u64::from_le_bytes(*b"rld\0\0\0\0\0"),
            u64::MAX,
        )
        .unwrap();
        assert_eq!(request.payload(), b"hello world");
        assert_eq!(
            SyscallRequest::decode(1, endpoint, receiver, 25, 0, 0, 0),
            Err(SyscallError::PayloadTooLarge)
        );
        assert_eq!(
            SyscallRequest::decode(1, 3, receiver, 0, 0, 0, 0),
            Err(SyscallError::InvalidCapability)
        );
        assert_eq!(
            SyscallRequest::decode(1, endpoint, 2, 0, 0, 0, 0),
            Err(SyscallError::InvalidTask)
        );
    }

    #[test]
    fn buffered_calls_bound_addresses_lengths_and_capability_descriptors() {
        let endpoint = (7u64 << 32) | 3;
        let receiver = (9u64 << 32) | 2;
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 368, 0x7000, 5),
            Ok(SyscallRequest::SendBuffer {
                endpoint: Capability::from_token(endpoint),
                receiver: TaskId::from_token(receiver),
                payload_address: 0x6000,
                payload_length: 368,
                capabilities_address: 0x7000,
                capability_count: 5,
            })
        );
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, 0x9000, 8, 0, 0),
            Ok(SyscallRequest::ReceiveBuffer {
                payload_address: 0x8000,
                payload_capacity: 112,
                capabilities_address: 0x9000,
                capability_capacity: 8,
            })
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0, 48, 0, 0),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, (1 << 47) - 32, 48, 0, 0),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 0, 0, 0),
            Err(SyscallError::PayloadTooLarge)
        );
        assert_eq!(
            SyscallRequest::decode(
                4,
                endpoint,
                receiver,
                0x6000,
                MAX_INLINE_PAYLOAD as u64 + 1,
                0,
                0,
            ),
            Err(SyscallError::PayloadTooLarge)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 48, 0, 1),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 48, 0x7001, 1),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 48, (1 << 47) - 8, 1),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 48, 0x6020, 1),
            Err(SyscallError::InvalidBuffer)
        );
        assert!(matches!(
            SyscallRequest::decode(4, endpoint, receiver, 0x6000, 48, 0x6030, 1),
            Ok(SyscallRequest::SendBuffer { .. })
        ));
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, (1 << 47) - 8, 1, 0, 0),
            Ok(SyscallRequest::ReceiveBuffer {
                payload_address: 0x8000,
                payload_capacity: 112,
                capabilities_address: (1 << 47) - 8,
                capability_capacity: 1,
            })
        );
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, (1 << 47) - 8, 2, 0, 0),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, 0x8068, 1, 0, 0),
            Err(SyscallError::InvalidBuffer)
        );
        assert!(matches!(
            SyscallRequest::decode(5, 0x8000, 112, 0x8070, 1, 0, 0),
            Ok(SyscallRequest::ReceiveBuffer { .. })
        ));
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, 0, 0, 1, 0),
            Err(SyscallError::ReservedArgument)
        );
        assert_eq!(
            SyscallRequest::decode(5, (1 << 47) - 64, 112, 0, 0, 0, 0),
            Err(SyscallError::InvalidBuffer)
        );
        assert_eq!(
            SyscallRequest::decode(5, 0x8000, 112, 0, MAX_CAPABILITIES as u64 + 1, 0, 0),
            Err(SyscallError::TooManyCapabilities)
        );
    }

    #[test]
    fn capability_authorization_binds_handle_object_and_rights() {
        let token = (7u64 << 32) | 3;
        assert_eq!(
            SyscallRequest::decode(6, token, 0x42, u64::from(Rights::READ.bits()), 0, 0, 0),
            Ok(SyscallRequest::AuthorizeCapability {
                capability: Capability::from_token(token),
                object: ObjectId(0x42),
                rights: Rights::READ,
            })
        );
        assert_eq!(
            SyscallRequest::decode(6, token, 0, u64::from(Rights::READ.bits()), 0, 0, 0),
            Err(SyscallError::InvalidObject)
        );
        assert_eq!(
            SyscallRequest::decode(6, token, 0x42, 0, 0, 0, 0),
            Err(SyscallError::InvalidRights)
        );
        assert_eq!(
            SyscallRequest::decode(6, token, 0x42, 1 << 16, 0, 0, 0),
            Err(SyscallError::InvalidRights)
        );
        assert_eq!(
            SyscallRequest::decode(6, token, 0x42, u64::from(Rights::READ.bits()), 1, 0, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn shared_buffer_calls_are_capability_selected_and_range_bounded() {
        let token = (8u64 << 32) | 4;
        assert_eq!(
            SyscallRequest::decode(7, token, 17, 0x6000, 4096, 0, 0),
            Ok(SyscallRequest::ReadSharedBuffer {
                capability: Capability::from_token(token),
                offset: 17,
                output_address: 0x6000,
                length: 4096,
            })
        );
        assert_eq!(
            SyscallRequest::decode(8, token, 29, 0x7000, 8192, 0, 0),
            Ok(SyscallRequest::WriteSharedBuffer {
                capability: Capability::from_token(token),
                offset: 29,
                input_address: 0x7000,
                length: 8192,
            })
        );
        for operation in [7, 8] {
            assert_eq!(
                SyscallRequest::decode(operation, 4, 0, 0x6000, 1, 0, 0),
                Err(SyscallError::InvalidCapability)
            );
            assert_eq!(
                SyscallRequest::decode(operation, token, 0, 0x6000, 0, 0, 0),
                Err(SyscallError::InvalidBuffer)
            );
            assert_eq!(
                SyscallRequest::decode(
                    operation,
                    token,
                    0,
                    0x6000,
                    MAX_SHARED_BUFFER_SYSCALL_BYTES as u64 + 1,
                    0,
                    0,
                ),
                Err(SyscallError::InvalidBuffer)
            );
            assert_eq!(
                SyscallRequest::decode(operation, token, 0, (1 << 47) - 1, 2, 0, 0),
                Err(SyscallError::InvalidBuffer)
            );
            assert_eq!(
                SyscallRequest::decode(operation, token, u64::MAX, 0x6000, 2, 0, 0),
                Err(SyscallError::InvalidBuffer)
            );
            assert_eq!(
                SyscallRequest::decode(operation, token, 0, 0x6000, 1, 1, 0),
                Err(SyscallError::ReservedArgument)
            );
        }
    }

    #[test]
    fn service_query_binds_exact_capability_and_generation() {
        let capability = (9u64 << 32) | 2;
        let service = (7u64 << 32) | 1;
        assert_eq!(
            SyscallRequest::decode(9, capability, service, 0, 0, 0, 0),
            Ok(SyscallRequest::QueryService {
                capability: Capability::from_token(capability),
                service: crate::ServiceId::from_token(service),
            })
        );
        assert_eq!(
            SyscallRequest::decode(9, 2, service, 0, 0, 0, 0),
            Err(SyscallError::InvalidCapability)
        );
        assert_eq!(
            SyscallRequest::decode(9, capability, 1, 0, 0, 0, 0),
            Err(SyscallError::InvalidObject)
        );
        assert_eq!(
            SyscallRequest::decode(9, capability, service, 0, 1, 0, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn service_state_completion_is_bounded_and_detail_free() {
        let mut frame = valid_yield_frame();
        frame.r10 = u64::MAX;
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_service_state(Some(crate::ServiceState::Faulted));
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (0, 3, 0, 0, 0)
        );
        frame.complete_service_state(None);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (1, 0, 0, 0, 0)
        );
    }

    #[test]
    fn service_restart_request_carries_no_context_or_time() {
        let capability = (11u64 << 32) | 2;
        let service = (12u64 << 32) | 1;
        assert_eq!(
            SyscallRequest::decode(10, capability, service, 0, 0, 0, 0),
            Ok(SyscallRequest::RestartService {
                capability: Capability::from_token(capability),
                service: crate::ServiceId::from_token(service),
            })
        );
        for reserved in [2, 3, 4, 5] {
            let mut registers = [0; 4];
            registers[reserved - 2] = 1;
            assert_eq!(
                SyscallRequest::decode(
                    10,
                    capability,
                    service,
                    registers[0],
                    registers[1],
                    registers[2],
                    registers[3],
                ),
                Err(SyscallError::ReservedArgument)
            );
        }
    }

    #[test]
    fn service_restart_completion_returns_only_fresh_generation() {
        let replacement = crate::ServiceId::from_token((13u64 << 32) | 4);
        let mut frame = valid_yield_frame();
        frame.complete_service_restart(Some(replacement));
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (0, replacement.token(), 0, 0, 0)
        );
        frame.complete_service_restart(None);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (1, 0, 0, 0, 0)
        );
    }

    #[test]
    fn service_policy_replacement_is_bounded_and_pointer_free() {
        let capability = (14u64 << 32) | 2;
        let service = (15u64 << 32) | 1;
        let policy = crate::RestartPolicy::new(3, 10, 40).unwrap();
        assert_eq!(
            SyscallRequest::decode(11, capability, service, 3, 10, 40, 0),
            Ok(SyscallRequest::ReplaceServicePolicy {
                capability: Capability::from_token(capability),
                service: crate::ServiceId::from_token(service),
                policy,
            })
        );
        assert_eq!(
            SyscallRequest::decode(11, 2, service, 3, 10, 40, 0),
            Err(SyscallError::InvalidCapability)
        );
        assert_eq!(
            SyscallRequest::decode(11, capability, 1, 3, 10, 40, 0),
            Err(SyscallError::InvalidObject)
        );
        for (maximum_restarts, base, maximum) in
            [(0, 0, 0), (1, 2, 1), (u64::from(u32::MAX) + 1, 0, 0)]
        {
            assert_eq!(
                SyscallRequest::decode(11, capability, service, maximum_restarts, base, maximum, 0,),
                Err(SyscallError::InvalidPolicy)
            );
        }
        assert_eq!(
            SyscallRequest::decode(11, capability, service, 3, 10, 40, 1),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn capability_release_is_exact_and_has_no_ambient_arguments() {
        let token = (17u64 << 32) | 3;
        assert_eq!(
            SyscallRequest::decode(12, token, 0, 0, 0, 0, 0),
            Ok(SyscallRequest::ReleaseCapability {
                capability: Capability::from_token(token),
            })
        );
        assert_eq!(
            SyscallRequest::decode(12, 3, 0, 0, 0, 0, 0),
            Err(SyscallError::InvalidCapability)
        );
        assert_eq!(
            SyscallRequest::decode(12, token, 1, 0, 0, 0, 0),
            Err(SyscallError::ReservedArgument)
        );
    }

    #[test]
    fn policy_replacement_completion_is_detail_free() {
        let mut frame = valid_yield_frame();
        frame.rdx = u64::MAX;
        frame.r10 = u64::MAX;
        frame.r8 = u64::MAX;
        frame.r9 = u64::MAX;
        frame.complete_policy_replacement(true);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (0, 0, 0, 0, 0)
        );
        frame.complete_policy_replacement(false);
        assert_eq!(
            (frame.rax, frame.rdx, frame.r10, frame.r8, frame.r9),
            (1, 0, 0, 0, 0)
        );
    }

    #[test]
    fn capability_transfer_descriptors_are_exact_and_canonical() {
        let capability = Capability::from_token((4u64 << 32) | 2);
        let mut wire = [0u8; CAPABILITY_TRANSFER_DESCRIPTOR_BYTES * 2];
        wire[..8].copy_from_slice(&capability.token().to_le_bytes());
        wire[8..10].copy_from_slice(&Rights::READ.bits().to_le_bytes());
        wire[16..24].copy_from_slice(&((5u64 << 32) | 3).to_le_bytes());
        wire[24..26].copy_from_slice(&Rights::WRITE.bits().to_le_bytes());
        let mut decoded = [None; MAX_CAPABILITIES];
        decode_capability_transfers(&wire, 2, &mut decoded).unwrap();
        assert_eq!(
            decoded[0],
            Some(CapabilityTransferDescriptor {
                capability,
                rights: Rights::READ,
            })
        );
        assert_eq!(
            decode_capability_transfers(&wire[..31], 2, &mut decoded),
            Err(SyscallError::InvalidBuffer)
        );
        wire[10] = 1;
        assert_eq!(
            decode_capability_transfers(&wire, 2, &mut decoded),
            Err(SyscallError::ReservedArgument)
        );
        wire[10] = 0;
        wire[8..10].copy_from_slice(&0x8000u16.to_le_bytes());
        let preserved = decoded;
        assert_eq!(
            decode_capability_transfers(&wire, 2, &mut decoded),
            Err(SyscallError::InvalidCapability)
        );
        assert_eq!(decoded, preserved);
    }

    #[test]
    fn capability_transfer_decode_failure_preserves_complete_output() {
        let seed = CapabilityTransferDescriptor {
            capability: Capability::from_token((7u64 << 32) | 1),
            rights: Rights::CONTROL,
        };
        let mut output = [Some(seed); MAX_CAPABILITIES];
        let mut wire = [0u8; CAPABILITY_TRANSFER_DESCRIPTOR_BYTES * 2];
        wire[..8].copy_from_slice(&((2u64 << 32) | 1).to_le_bytes());
        wire[8..10].copy_from_slice(&Rights::READ.bits().to_le_bytes());
        wire[16..24].copy_from_slice(&((3u64 << 32) | 1).to_le_bytes());
        wire[24..26].copy_from_slice(&Rights::WRITE.bits().to_le_bytes());
        wire[31] = 1;

        assert_eq!(
            decode_capability_transfers(&wire, 2, &mut output),
            Err(SyscallError::ReservedArgument)
        );
        assert_eq!(output, [Some(seed); MAX_CAPABILITIES]);
    }

    #[test]
    fn unknown_operations_fail_without_interpreting_arguments() {
        assert_eq!(
            SyscallRequest::decode(u64::MAX, 1, 2, 3, 4, 5, 6),
            Err(SyscallError::UnknownOperation)
        );
    }

    #[test]
    fn hardware_call_frame_is_exact_and_rejects_forged_return_state() {
        assert_eq!(core::mem::size_of::<UserCallFrame>(), 20 * 8);
        assert_eq!(core::mem::offset_of!(UserCallFrame, r15), 0);
        assert_eq!(core::mem::offset_of!(UserCallFrame, rax), 14 * 8);
        assert_eq!(core::mem::offset_of!(UserCallFrame, rip), 15 * 8);
        assert_eq!(core::mem::offset_of!(UserCallFrame, rsp), 18 * 8);
        let mut frame = valid_yield_frame();
        assert_eq!(frame.decode_request(), Ok(SyscallRequest::Yield));
        assert_eq!(frame.request(), Ok(SyscallRequest::Yield));
        frame.cs = 0x38;
        assert_eq!(
            frame.validate_return(),
            Err(UserReturnError::InvalidPrivilege)
        );
        assert_eq!(
            frame.decode_request(),
            Err(UserCallDecodeError::Return(
                UserReturnError::InvalidPrivilege
            ))
        );
        assert_eq!(frame.request(), Err(SyscallError::InvalidPrivilege));
        frame.cs = u64::from(USER_CODE_SELECTOR);
        frame.rip = 0xffff_8000_0000_0000;
        assert_eq!(
            frame.validate_return(),
            Err(UserReturnError::InvalidInstruction)
        );
        assert_eq!(frame.request(), Err(SyscallError::InvalidInstruction));
        frame.rip = 0x40_1000;
        frame.rsp = 0;
        assert_eq!(frame.validate_return(), Err(UserReturnError::InvalidStack));
        assert_eq!(frame.request(), Err(SyscallError::InvalidStack));
        frame.rsp = 0x7000_0000_0000;
        frame.rflags = 0;
        assert_eq!(frame.validate_return(), Err(UserReturnError::InvalidFlags));
        assert_eq!(frame.request(), Err(SyscallError::InvalidFlags));
        frame.rflags = 0x202 | (3 << 12);
        assert_eq!(frame.request(), Err(SyscallError::InvalidFlags));

        frame = valid_yield_frame();
        frame.rax = u64::MAX;
        assert_eq!(
            frame.decode_request(),
            Err(UserCallDecodeError::Request(SyscallError::UnknownOperation))
        );
    }

    fn valid_yield_frame() -> UserCallFrame {
        UserCallFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            rip: 0x40_1000,
            cs: u64::from(USER_CODE_SELECTOR),
            rflags: 0x202,
            rsp: 0x7000_0000,
            ss: u64::from(USER_DATA_SELECTOR),
        }
    }
}
