use mrml_crypto::Sha256;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_CC_NV_INCREMENT: u32 = 0x0000_0137;
const TPM_CC_NV_READ: u32 = 0x0000_014e;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const TPM_RC_SUCCESS: u32 = 0;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPMA_NV_POLICYWRITE: u32 = 1 << 3;
const TPMA_NV_TYPE_MASK: u32 = 0x0f << 4;
const TPMA_NV_COUNTER: u32 = 1 << 4;
const TPMA_NV_WRITEALL: u32 = 1 << 12;
const TPMA_NV_POLICYREAD: u32 = 1 << 19;
const TPMA_NV_NO_DA: u32 = 1 << 25;
const TPMA_NV_WRITTEN: u32 = 1 << 29;
const RECOVERY_SLOT_BYTES: u16 = 112;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvCounterError {
    InvalidIndex,
    Rollback,
    AdvanceLimit,
    Transport,
    MalformedResponse,
    Tpm(u32),
}

pub trait TpmTransport {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvRecoveryLayout {
    counter: u32,
    slots: [u32; 2],
    policy_digest: [u8; 32],
}

impl NvRecoveryLayout {
    pub fn new(
        counter: u32,
        slots: [u32; 2],
        policy_digest: [u8; 32],
    ) -> Result<Self, NvCounterError> {
        if !valid_index(counter)
            || slots.iter().any(|index| !valid_index(*index))
            || counter == slots[0]
            || counter == slots[1]
            || slots[0] == slots[1]
            || policy_digest.iter().all(|byte| *byte == 0)
        {
            return Err(NvCounterError::InvalidIndex);
        }
        Ok(Self {
            counter,
            slots,
            policy_digest,
        })
    }

    pub const fn counter(self) -> u32 {
        self.counter
    }

    pub const fn slots(self) -> [u32; 2] {
        self.slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNvRecoveryLayout {
    counter_name: [u8; 34],
    slot_names: [[u8; 34]; 2],
}

impl VerifiedNvRecoveryLayout {
    pub const fn counter_name(self) -> [u8; 34] {
        self.counter_name
    }

    pub const fn slot_names(self) -> [[u8; 34]; 2] {
        self.slot_names
    }
}

pub fn verify_recovery_layout<T: TpmTransport>(
    transport: &mut T,
    layout: NvRecoveryLayout,
) -> Result<VerifiedNvRecoveryLayout, NvCounterError> {
    let counter = read_public(transport, layout.counter)?;
    validate_recovery_public(
        counter,
        layout.counter,
        TPMA_NV_COUNTER,
        8,
        layout.policy_digest,
    )?;
    let first = read_public(transport, layout.slots[0])?;
    validate_recovery_public(
        first,
        layout.slots[0],
        0,
        RECOVERY_SLOT_BYTES,
        layout.policy_digest,
    )?;
    let second = read_public(transport, layout.slots[1])?;
    validate_recovery_public(
        second,
        layout.slots[1],
        0,
        RECOVERY_SLOT_BYTES,
        layout.policy_digest,
    )?;
    if counter.name == first.name || counter.name == second.name || first.name == second.name {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(VerifiedNvRecoveryLayout {
        counter_name: counter.name,
        slot_names: [first.name, second.name],
    })
}

pub fn enforce_version<T: TpmTransport>(
    transport: &mut T,
    index: u32,
    version: u64,
    maximum_advances: u64,
) -> Result<u64, NvCounterError> {
    if !(0x0100_0000..=0x01ff_ffff).contains(&index) || version == 0 {
        return Err(NvCounterError::InvalidIndex);
    }
    verify_counter_index(transport, index)?;
    let current = read_counter(transport, index)?;
    if current > version {
        return Err(NvCounterError::Rollback);
    }
    let advances = version - current;
    if advances > maximum_advances {
        return Err(NvCounterError::AdvanceLimit);
    }
    for _ in 0..advances {
        increment_counter(transport, index)?;
    }
    Ok(version)
}

pub fn verify_counter_index<T: TpmTransport>(
    transport: &mut T,
    index: u32,
) -> Result<(), NvCounterError> {
    if !(0x0100_0000..=0x01ff_ffff).contains(&index) {
        return Err(NvCounterError::InvalidIndex);
    }
    let public = read_public(transport, index)?;
    if public.index != index
        || public.attributes & TPMA_NV_TYPE_MASK != TPMA_NV_COUNTER
        || public.data_size != 8
    {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(())
}

fn read_public<T: TpmTransport>(transport: &mut T, index: u32) -> Result<NvPublic, NvCounterError> {
    let mut command = [0u8; 14];
    command[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&14u32.to_be_bytes());
    command[6..10].copy_from_slice(&TPM_CC_NV_READ_PUBLIC.to_be_bytes());
    command[10..14].copy_from_slice(&index.to_be_bytes());
    let mut response = [0u8; 128];
    let length = transport.submit(&command, &mut response)?;
    parse_public_response(&response[..length])
}

pub fn read_counter<T: TpmTransport>(transport: &mut T, index: u32) -> Result<u64, NvCounterError> {
    let mut command = [0u8; 35];
    sessions_header(&mut command, TPM_CC_NV_READ);
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    command[18..22].copy_from_slice(&9u32.to_be_bytes());
    password_session(&mut command[22..31]);
    command[31..33].copy_from_slice(&8u16.to_be_bytes());
    let mut response = [0u8; 64];
    let length = transport.submit(&command, &mut response)?;
    parse_counter_response(&response[..length])
}

pub fn increment_counter<T: TpmTransport>(
    transport: &mut T,
    index: u32,
) -> Result<(), NvCounterError> {
    let mut command = [0u8; 31];
    sessions_header(&mut command, TPM_CC_NV_INCREMENT);
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    command[18..22].copy_from_slice(&9u32.to_be_bytes());
    password_session(&mut command[22..31]);
    let mut response = [0u8; 32];
    let length = transport.submit(&command, &mut response)?;
    parse_empty_response(&response[..length])
}

fn sessions_header(command: &mut [u8], code: u32) {
    let length = command.len() as u32;
    command[..2].copy_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&length.to_be_bytes());
    command[6..10].copy_from_slice(&code.to_be_bytes());
}

fn password_session(output: &mut [u8]) {
    output[..4].copy_from_slice(&TPM_RS_PW.to_be_bytes());
    output[4..6].copy_from_slice(&0u16.to_be_bytes());
    output[6] = 0;
    output[7..9].copy_from_slice(&0u16.to_be_bytes());
}

fn response_header(response: &[u8]) -> Result<(u16, usize), NvCounterError> {
    if response.len() < 10 {
        return Err(NvCounterError::MalformedResponse);
    }
    let tag = u16::from_be_bytes([response[0], response[1]]);
    let declared = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
    let code = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if declared != response.len() || !matches!(tag, TPM_ST_NO_SESSIONS | TPM_ST_SESSIONS) {
        return Err(NvCounterError::MalformedResponse);
    }
    if code != TPM_RC_SUCCESS {
        return Err(NvCounterError::Tpm(code));
    }
    Ok((tag, declared))
}

fn parse_counter_response(response: &[u8]) -> Result<u64, NvCounterError> {
    let (tag, _) = response_header(response)?;
    if tag != TPM_ST_SESSIONS || response.len() < 24 {
        return Err(NvCounterError::MalformedResponse);
    }
    let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
    if parameter_size != 10 || response.len() != 14 + parameter_size + 5 {
        return Err(NvCounterError::MalformedResponse);
    }
    if u16::from_be_bytes(response[14..16].try_into().unwrap()) != 8 {
        return Err(NvCounterError::MalformedResponse);
    }
    parse_empty_auth(&response[24..])?;
    Ok(u64::from_be_bytes(response[16..24].try_into().unwrap()))
}

fn parse_empty_response(response: &[u8]) -> Result<(), NvCounterError> {
    let (tag, _) = response_header(response)?;
    if tag != TPM_ST_SESSIONS || response.len() != 19 {
        return Err(NvCounterError::MalformedResponse);
    }
    let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap());
    if parameter_size != 0 {
        return Err(NvCounterError::MalformedResponse);
    }
    parse_empty_auth(&response[14..])
}

#[derive(Clone, Copy)]
struct NvPublic {
    index: u32,
    name_algorithm: u16,
    attributes: u32,
    policy_size: u16,
    policy_digest: [u8; 32],
    data_size: u16,
    name: [u8; 34],
}

fn parse_public_response(response: &[u8]) -> Result<NvPublic, NvCounterError> {
    let (tag, _) = response_header(response)?;
    if tag != TPM_ST_NO_SESSIONS || response.len() < 28 {
        return Err(NvCounterError::MalformedResponse);
    }
    let public_size = u16::from_be_bytes(response[10..12].try_into().unwrap()) as usize;
    let public_end = 12usize
        .checked_add(public_size)
        .ok_or(NvCounterError::MalformedResponse)?;
    if public_size < 14 || public_end + 2 > response.len() {
        return Err(NvCounterError::MalformedResponse);
    }
    let public = &response[12..public_end];
    let index = u32::from_be_bytes(public[..4].try_into().unwrap());
    let name_algorithm = u16::from_be_bytes(public[4..6].try_into().unwrap());
    let attributes = u32::from_be_bytes(public[6..10].try_into().unwrap());
    let policy_size = u16::from_be_bytes(public[10..12].try_into().unwrap()) as usize;
    let data_size_at = 12usize
        .checked_add(policy_size)
        .ok_or(NvCounterError::MalformedResponse)?;
    if data_size_at + 2 != public.len() || policy_size > 32 {
        return Err(NvCounterError::MalformedResponse);
    }
    let data_size = u16::from_be_bytes(public[data_size_at..data_size_at + 2].try_into().unwrap());
    let mut policy_digest = [0; 32];
    policy_digest[..policy_size].copy_from_slice(&public[12..12 + policy_size]);
    let name_size =
        u16::from_be_bytes(response[public_end..public_end + 2].try_into().unwrap()) as usize;
    if name_size != 34 || public_end + 2 + name_size != response.len() {
        return Err(NvCounterError::MalformedResponse);
    }
    let name: [u8; 34] = response[public_end + 2..].try_into().unwrap();
    let expected_digest = Sha256::digest(public);
    if name[..2] != name_algorithm.to_be_bytes() || name[2..] != expected_digest {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(NvPublic {
        index,
        name_algorithm,
        attributes,
        policy_size: policy_size as u16,
        policy_digest,
        data_size,
        name,
    })
}

fn validate_recovery_public(
    public: NvPublic,
    expected_index: u32,
    expected_type: u32,
    expected_size: u16,
    expected_policy: [u8; 32],
) -> Result<(), NvCounterError> {
    let required = TPMA_NV_POLICYWRITE
        | TPMA_NV_POLICYREAD
        | TPMA_NV_NO_DA
        | expected_type
        | if expected_type == 0 {
            TPMA_NV_WRITEALL
        } else {
            0
        };
    if public.index != expected_index
        || public.name_algorithm != TPM_ALG_SHA256
        || public.data_size != expected_size
        || public.policy_size != 32
        || public.policy_digest != expected_policy
        || public.attributes & !TPMA_NV_WRITTEN != required
    {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(())
}

const fn valid_index(index: u32) -> bool {
    index >= 0x0100_0000 && index <= 0x01ff_ffff
}

fn parse_empty_auth(response: &[u8]) -> Result<(), NvCounterError> {
    if response == [0, 0, 0, 0, 0] {
        Ok(())
    } else {
        Err(NvCounterError::MalformedResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter {
        value: u64,
        calls: usize,
        attributes: u32,
        data_size: u16,
    }

    fn public_response(
        response: &mut [u8],
        index: u32,
        attributes: u32,
        policy: &[u8],
        data_size: u16,
        corrupt_name: bool,
    ) -> usize {
        let public_size = 14 + policy.len();
        let public_end = 12 + public_size;
        let length = public_end + 2 + 34;
        response[..length].fill(0);
        response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        response[2..6].copy_from_slice(&(length as u32).to_be_bytes());
        response[10..12].copy_from_slice(&(public_size as u16).to_be_bytes());
        response[12..16].copy_from_slice(&index.to_be_bytes());
        response[16..18].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        response[18..22].copy_from_slice(&attributes.to_be_bytes());
        response[22..24].copy_from_slice(&(policy.len() as u16).to_be_bytes());
        response[24..24 + policy.len()].copy_from_slice(policy);
        response[24 + policy.len()..26 + policy.len()].copy_from_slice(&data_size.to_be_bytes());
        response[public_end..public_end + 2].copy_from_slice(&34u16.to_be_bytes());
        response[public_end + 2..public_end + 4].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        let digest = Sha256::digest(&response[12..public_end]);
        response[public_end + 4..length].copy_from_slice(&digest);
        if corrupt_name {
            response[length - 1] ^= 1;
        }
        length
    }

    impl TpmTransport for Counter {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            self.calls += 1;
            let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
            if code == TPM_CC_NV_READ_PUBLIC {
                let index = u32::from_be_bytes(command[10..14].try_into().unwrap());
                return Ok(public_response(
                    response,
                    index,
                    self.attributes,
                    &[],
                    self.data_size,
                    false,
                ));
            }
            if code == TPM_CC_NV_INCREMENT {
                self.value += 1;
                response[..19].copy_from_slice(&[
                    0x80, 0x02, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]);
                return Ok(19);
            }
            response[..29].copy_from_slice(&[
                0x80, 0x02, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 10, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            response[16..24].copy_from_slice(&self.value.to_be_bytes());
            Ok(29)
        }
    }

    #[test]
    fn advances_monotonically_and_rejects_rollback() {
        let mut counter = Counter {
            value: 3,
            calls: 0,
            attributes: 0x10,
            data_size: 8,
        };
        assert_eq!(enforce_version(&mut counter, 0x0180_0001, 5, 8), Ok(5));
        assert_eq!(counter.value, 5);
        assert_eq!(counter.calls, 4);
        assert_eq!(
            enforce_version(&mut counter, 0x0180_0001, 4, 8),
            Err(NvCounterError::Rollback)
        );
    }

    #[test]
    fn bounds_advancement_and_rejects_malformed_responses() {
        let mut counter = Counter {
            value: 1,
            calls: 0,
            attributes: 0x10,
            data_size: 8,
        };
        assert_eq!(
            enforce_version(&mut counter, 0x0180_0001, 10, 4),
            Err(NvCounterError::AdvanceLimit)
        );
        assert_eq!(
            response_header(&[0; 9]),
            Err(NvCounterError::MalformedResponse)
        );
        counter.attributes = 0;
        assert_eq!(
            enforce_version(&mut counter, 0x0180_0001, 1, 4),
            Err(NvCounterError::InvalidIndex)
        );
        counter.attributes = 0x10;
        counter.data_size = 16;
        assert_eq!(
            enforce_version(&mut counter, 0x0180_0001, 1, 4),
            Err(NvCounterError::InvalidIndex)
        );
    }

    struct LayoutTransport {
        policy: [u8; 32],
        corrupt_name: bool,
        extra_attributes: u32,
        wrong_slot_size: bool,
    }

    impl TpmTransport for LayoutTransport {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            if u32::from_be_bytes(command[6..10].try_into().unwrap()) != TPM_CC_NV_READ_PUBLIC {
                return Err(NvCounterError::Transport);
            }
            let index = u32::from_be_bytes(command[10..14].try_into().unwrap());
            let counter = index == 0x0180_0010;
            let attributes = TPMA_NV_POLICYWRITE
                | TPMA_NV_POLICYREAD
                | TPMA_NV_NO_DA
                | if counter {
                    TPMA_NV_COUNTER
                } else {
                    TPMA_NV_WRITEALL
                }
                | self.extra_attributes;
            Ok(public_response(
                response,
                index,
                attributes,
                &self.policy,
                if counter {
                    8
                } else if self.wrong_slot_size {
                    111
                } else {
                    RECOVERY_SLOT_BYTES
                },
                self.corrupt_name,
            ))
        }
    }

    fn layout(policy: [u8; 32]) -> NvRecoveryLayout {
        NvRecoveryLayout::new(0x0180_0010, [0x0180_0011, 0x0180_0012], policy).unwrap()
    }

    #[test]
    fn admits_only_exact_policy_bound_recovery_layout() {
        let policy = [0x5a; 32];
        let mut transport = LayoutTransport {
            policy,
            corrupt_name: false,
            extra_attributes: 0,
            wrong_slot_size: false,
        };
        let verified = verify_recovery_layout(&mut transport, layout(policy)).unwrap();
        assert_eq!(&verified.counter_name()[..2], &TPM_ALG_SHA256.to_be_bytes());
        assert_ne!(verified.slot_names()[0], verified.slot_names()[1]);

        transport.policy = [0x6b; 32];
        assert_eq!(
            verify_recovery_layout(&mut transport, layout(policy)),
            Err(NvCounterError::InvalidIndex)
        );
        transport.policy = policy;
        transport.corrupt_name = true;
        assert_eq!(
            verify_recovery_layout(&mut transport, layout(policy)),
            Err(NvCounterError::InvalidIndex)
        );
        transport.corrupt_name = false;
        transport.extra_attributes = 1 << 2;
        assert_eq!(
            verify_recovery_layout(&mut transport, layout(policy)),
            Err(NvCounterError::InvalidIndex)
        );
        transport.extra_attributes = 0;
        transport.wrong_slot_size = true;
        assert_eq!(
            verify_recovery_layout(&mut transport, layout(policy)),
            Err(NvCounterError::InvalidIndex)
        );
    }

    #[test]
    fn recovery_layout_rejects_aliases_and_empty_policy() {
        assert_eq!(
            NvRecoveryLayout::new(0x0180_0010, [0x0180_0010, 0x0180_0012], [1; 32]),
            Err(NvCounterError::InvalidIndex)
        );
        assert_eq!(
            NvRecoveryLayout::new(0x0180_0010, [0x0180_0011, 0x0180_0012], [0; 32]),
            Err(NvCounterError::InvalidIndex)
        );

        let mut response = [0; 128];
        let length = public_response(
            &mut response,
            0x0180_0010,
            TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA | TPMA_NV_COUNTER,
            &[1],
            8,
            false,
        );
        let public = parse_public_response(&response[..length]).unwrap();
        let mut padded_policy = [0; 32];
        padded_policy[0] = 1;
        assert_eq!(
            validate_recovery_public(public, 0x0180_0010, TPMA_NV_COUNTER, 8, padded_policy,),
            Err(NvCounterError::InvalidIndex)
        );
    }
}
