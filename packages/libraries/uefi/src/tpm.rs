use mrml_crypto::Sha256;
use mrml_storage::{
    AuthenticatedRecoveryJournal, AuthenticatedReleaseStateJournal, RECOVERY_JOURNAL_SLOT_BYTES,
    RELEASE_STATE_JOURNAL_SLOT_BYTES, RecoveryJournalBackend, ReleaseStateJournalBackend,
};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
const TPM_CC_NV_READ: u32 = 0x0000_014e;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
const TPM_RC_SUCCESS: u32 = 0;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_SE_POLICY: u8 = 0x01;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPMA_NV_POLICYWRITE: u32 = 1 << 3;
const TPMA_NV_TYPE_MASK: u32 = 0x0f << 4;
const TPMA_NV_COUNTER: u32 = 1 << 4;
const TPMA_NV_WRITEALL: u32 = 1 << 12;
const TPMA_NV_POLICYREAD: u32 = 1 << 19;
const TPMA_NV_NO_DA: u32 = 1 << 25;
const TPMA_NV_WRITTEN: u32 = 1 << 29;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvCounterError {
    InvalidIndex,
    Rollback,
    AdvanceLimit,
    Transport,
    MalformedResponse,
    Conflict,
    InvalidSession,
    Tpm(u32),
}

pub trait TpmTransport {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvPolicyOperation {
    Read,
    Write,
    Increment,
}

/// One-use TPM policy session already satisfied for one exact NV operation.
pub struct AuthorizedNvSession {
    handle: u32,
}

impl AuthorizedNvSession {
    /// # Safety
    ///
    /// `handle` must name a live, freshly satisfied policy session bound to the
    /// exact Name, policy digest, and operation supplied to the provider. The
    /// session must be consumed by the immediately following TPM command and
    /// must not be returned twice.
    pub const unsafe fn from_satisfied_policy(handle: u32) -> Self {
        Self { handle }
    }
}

/// Owner-policy boundary that creates fresh one-use TPM policy sessions.
///
/// # Safety
///
/// Implementations must authenticate the owner-approved policy, bind the
/// session to `index`, `name`, `policy_digest`, and `operation`, serialize the
/// NV domain, and never return the same live session twice.
pub unsafe trait NvPolicySessionProvider: TpmTransport {
    fn authorize_nv(
        &mut self,
        index: u32,
        name: [u8; 34],
        policy_digest: [u8; 32],
        operation: NvPolicyOperation,
    ) -> Result<AuthorizedNvSession, NvCounterError>;
}

pub trait TpmNonceSource {
    fn fill_nonce(&mut self, output: &mut [u8; 32]) -> Result<(), NvCounterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcrPolicy {
    policy_digest: [u8; 32],
    expected_pcr_digest: [u8; 32],
    pcr_select: [u8; 3],
}

impl PcrPolicy {
    pub fn new(
        policy_digest: [u8; 32],
        expected_pcr_digest: [u8; 32],
        pcr_select: [u8; 3],
    ) -> Result<Self, NvCounterError> {
        if policy_digest.iter().all(|byte| *byte == 0)
            || expected_pcr_digest.iter().all(|byte| *byte == 0)
            || pcr_select.iter().all(|byte| *byte == 0)
        {
            return Err(NvCounterError::InvalidSession);
        }
        Ok(Self {
            policy_digest,
            expected_pcr_digest,
            pcr_select,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryJournalConfiguration {
    layout: NvRecoveryLayout,
    policy: PcrPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseStateJournalConfiguration {
    layout: NvReleaseStateLayout,
    policy: PcrPolicy,
}

impl ReleaseStateJournalConfiguration {
    pub fn parse_optional(fields: [Option<&[u8]>; 6]) -> Result<Option<Self>, NvCounterError> {
        match fields {
            [None, None, None, None, None, None] => Ok(None),
            [
                Some(counter),
                Some(slot_zero),
                Some(slot_one),
                Some(policy),
                Some(pcr),
                Some(select),
            ] => Self::parse(counter, slot_zero, slot_one, policy, pcr, select).map(Some),
            _ => Err(NvCounterError::InvalidIndex),
        }
    }

    pub fn parse(
        counter_index: &[u8],
        slot_zero_index: &[u8],
        slot_one_index: &[u8],
        policy_digest: &[u8],
        expected_pcr_digest: &[u8],
        pcr_select: &[u8],
    ) -> Result<Self, NvCounterError> {
        let policy_digest = parse_hex_exact::<32>(policy_digest)?;
        let layout = NvReleaseStateLayout::new(
            parse_hex_u32(counter_index)?,
            [
                parse_hex_u32(slot_zero_index)?,
                parse_hex_u32(slot_one_index)?,
            ],
            policy_digest,
        )?;
        let policy = PcrPolicy::new(
            policy_digest,
            parse_hex_exact::<32>(expected_pcr_digest)?,
            parse_hex_exact::<3>(pcr_select)?,
        )?;
        Ok(Self { layout, policy })
    }

    pub const fn into_parts(self) -> (NvReleaseStateLayout, PcrPolicy) {
        (self.layout, self.policy)
    }
}

impl RecoveryJournalConfiguration {
    pub fn parse_optional(fields: [Option<&[u8]>; 6]) -> Result<Option<Self>, NvCounterError> {
        match fields {
            [None, None, None, None, None, None] => Ok(None),
            [
                Some(counter),
                Some(slot_zero),
                Some(slot_one),
                Some(policy),
                Some(pcr),
                Some(select),
            ] => Self::parse(counter, slot_zero, slot_one, policy, pcr, select).map(Some),
            _ => Err(NvCounterError::InvalidIndex),
        }
    }

    pub fn parse(
        counter_index: &[u8],
        slot_zero_index: &[u8],
        slot_one_index: &[u8],
        policy_digest: &[u8],
        expected_pcr_digest: &[u8],
        pcr_select: &[u8],
    ) -> Result<Self, NvCounterError> {
        let policy_digest = parse_hex_exact::<32>(policy_digest)?;
        let layout = NvRecoveryLayout::new(
            parse_hex_u32(counter_index)?,
            [
                parse_hex_u32(slot_zero_index)?,
                parse_hex_u32(slot_one_index)?,
            ],
            policy_digest,
        )?;
        let policy = PcrPolicy::new(
            policy_digest,
            parse_hex_exact::<32>(expected_pcr_digest)?,
            parse_hex_exact::<3>(pcr_select)?,
        )?;
        Ok(Self { layout, policy })
    }

    pub const fn into_parts(self) -> (NvRecoveryLayout, PcrPolicy) {
        (self.layout, self.policy)
    }
}

fn parse_hex_u32(input: &[u8]) -> Result<u32, NvCounterError> {
    Ok(u32::from_be_bytes(parse_hex_exact::<4>(input)?))
}

fn parse_hex_exact<const N: usize>(input: &[u8]) -> Result<[u8; N], NvCounterError> {
    if input.len() != N * 2 {
        return Err(NvCounterError::InvalidIndex);
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(input[index * 2]).ok_or(NvCounterError::InvalidIndex)?;
        let low = hex_nibble(input[index * 2 + 1]).ok_or(NvCounterError::InvalidIndex)?;
        *byte = high << 4 | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Concrete one-use provider for an owner-configured SHA-256 `PolicyPCR`
/// recipe. It serializes one pending NV authorization at a time.
trait NvPolicyObjectAdmission: Copy {
    fn admits(self, index: u32, name: [u8; 34], policy_digest: [u8; 32]) -> bool;
}

pub struct PcrPolicySessionTransport<T, N, A = VerifiedNvRecoveryLayout> {
    transport: T,
    nonce_source: N,
    policy: PcrPolicy,
    verified: A,
    pending: Option<(u32, u32, NvPolicyOperation)>,
    last_nonce: Option<[u8; 32]>,
}

impl<T, N, A> PcrPolicySessionTransport<T, N, A> {
    const fn new(transport: T, nonce_source: N, policy: PcrPolicy, verified: A) -> Self {
        Self {
            transport,
            nonce_source,
            policy,
            verified,
            pending: None,
            last_nonce: None,
        }
    }

    pub fn into_parts(self) -> (T, N) {
        (self.transport, self.nonce_source)
    }
}

impl<T: TpmTransport, N, A> TpmTransport for PcrPolicySessionTransport<T, N, A> {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
        let pending = self.pending.take();
        if let Some((handle, index, operation)) = pending
            && (command.len() < 31
                || u32::from_be_bytes(command[10..14].try_into().unwrap()) != index
                || u32::from_be_bytes(command[14..18].try_into().unwrap()) != index
                || u32::from_be_bytes(command[22..26].try_into().unwrap()) != handle
                || operation_for_command(command) != Some(operation))
        {
            let _ = flush_context(&mut self.transport, handle);
            return Err(NvCounterError::InvalidSession);
        }
        match self.transport.submit(command, response) {
            Ok(length) => Ok(length),
            Err(error) => {
                // The transport cannot prove whether the TPM consumed a command
                // that failed in flight. Retire the satisfied session in either
                // case; an already-consumed handle simply makes this best-effort
                // cleanup fail harmlessly.
                if let Some((handle, _, _)) = pending {
                    let _ = flush_context(&mut self.transport, handle);
                }
                Err(error)
            }
        }
    }
}

// SAFETY: the wrapper creates a fresh TPM policy session from explicit entropy,
// executes the exact configured PolicyPCR recipe, permits only one pending
// command with the requested operation/handle, and flushes mismatched use.
unsafe impl<T: TpmTransport, N: TpmNonceSource, A: NvPolicyObjectAdmission> NvPolicySessionProvider
    for PcrPolicySessionTransport<T, N, A>
{
    fn authorize_nv(
        &mut self,
        index: u32,
        name: [u8; 34],
        policy_digest: [u8; 32],
        operation: NvPolicyOperation,
    ) -> Result<AuthorizedNvSession, NvCounterError> {
        if self.pending.is_some()
            || !valid_index(index)
            || policy_digest != self.policy.policy_digest
            || !self.verified.admits(index, name, policy_digest)
        {
            return Err(NvCounterError::InvalidSession);
        }
        let mut nonce = [0; 32];
        self.nonce_source.fill_nonce(&mut nonce)?;
        if nonce.iter().all(|byte| *byte == 0) || self.last_nonce == Some(nonce) {
            return Err(NvCounterError::InvalidSession);
        }
        self.last_nonce = Some(nonce);
        let handle = start_policy_session(&mut self.transport, nonce)?;
        if let Err(error) = execute_policy_pcr(&mut self.transport, handle, self.policy) {
            let _ = flush_context(&mut self.transport, handle);
            return Err(error);
        }
        self.pending = Some((handle, index, operation));
        Ok(unsafe { AuthorizedNvSession::from_satisfied_policy(handle) })
    }
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
    counter: u32,
    counter_name: [u8; 34],
    slots: [u32; 2],
    slot_names: [[u8; 34]; 2],
    policy_digest: [u8; 32],
}

impl VerifiedNvRecoveryLayout {
    pub const fn counter_name(self) -> [u8; 34] {
        self.counter_name
    }

    pub const fn slot_names(self) -> [[u8; 34]; 2] {
        self.slot_names
    }

    fn admits(self, index: u32, name: [u8; 34], policy_digest: [u8; 32]) -> bool {
        if policy_digest != self.policy_digest {
            return false;
        }
        if index == self.counter {
            return name == self.counter_name;
        }
        if index == self.slots[0] {
            return name == self.slot_names[0];
        }
        if index == self.slots[1] {
            return name == self.slot_names[1];
        }
        false
    }
}

impl NvPolicyObjectAdmission for VerifiedNvRecoveryLayout {
    fn admits(self, index: u32, name: [u8; 34], policy_digest: [u8; 32]) -> bool {
        self.admits(index, name, policy_digest)
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
        RECOVERY_JOURNAL_SLOT_BYTES as u16,
        layout.policy_digest,
    )?;
    let second = read_public(transport, layout.slots[1])?;
    validate_recovery_public(
        second,
        layout.slots[1],
        0,
        RECOVERY_JOURNAL_SLOT_BYTES as u16,
        layout.policy_digest,
    )?;
    if counter.name == first.name || counter.name == second.name || first.name == second.name {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(VerifiedNvRecoveryLayout {
        counter: layout.counter,
        counter_name: counter.name,
        slots: layout.slots,
        slot_names: [first.name, second.name],
        policy_digest: layout.policy_digest,
    })
}

/// Owner-provisioned NV objects dedicated to the release bootstrap journal.
/// These indices must not alias the recovery-authority journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvReleaseStateLayout {
    counter: u32,
    slots: [u32; 2],
    policy_digest: [u8; 32],
}

impl NvReleaseStateLayout {
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

/// Rejects any numeric NV-index alias between the two journal domains before
/// either layout is provisioned or opened.
pub fn verify_distinct_journal_layouts(
    recovery: NvRecoveryLayout,
    release: NvReleaseStateLayout,
) -> Result<(), NvCounterError> {
    let recovery_indices = [recovery.counter, recovery.slots[0], recovery.slots[1]];
    let release_indices = [release.counter, release.slots[0], release.slots[1]];
    if recovery_indices
        .iter()
        .any(|index| release_indices.contains(index))
    {
        Err(NvCounterError::InvalidIndex)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNvReleaseStateLayout {
    counter: u32,
    counter_name: [u8; 34],
    slots: [u32; 2],
    slot_names: [[u8; 34]; 2],
    policy_digest: [u8; 32],
}

impl VerifiedNvReleaseStateLayout {
    pub const fn counter_name(self) -> [u8; 34] {
        self.counter_name
    }

    pub const fn slot_names(self) -> [[u8; 34]; 2] {
        self.slot_names
    }
}

impl NvPolicyObjectAdmission for VerifiedNvReleaseStateLayout {
    fn admits(self, index: u32, name: [u8; 34], policy_digest: [u8; 32]) -> bool {
        if policy_digest != self.policy_digest {
            return false;
        }
        if index == self.counter {
            return name == self.counter_name;
        }
        if index == self.slots[0] {
            return name == self.slot_names[0];
        }
        index == self.slots[1] && name == self.slot_names[1]
    }
}

pub fn verify_release_state_layout<T: TpmTransport>(
    transport: &mut T,
    layout: NvReleaseStateLayout,
) -> Result<VerifiedNvReleaseStateLayout, NvCounterError> {
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
        RELEASE_STATE_JOURNAL_SLOT_BYTES as u16,
        layout.policy_digest,
    )?;
    let second = read_public(transport, layout.slots[1])?;
    validate_recovery_public(
        second,
        layout.slots[1],
        0,
        RELEASE_STATE_JOURNAL_SLOT_BYTES as u16,
        layout.policy_digest,
    )?;
    if counter.name == first.name || counter.name == second.name || first.name == second.name {
        return Err(NvCounterError::InvalidIndex);
    }
    Ok(VerifiedNvReleaseStateLayout {
        counter: layout.counter,
        counter_name: counter.name,
        slots: layout.slots,
        slot_names: [first.name, second.name],
        policy_digest: layout.policy_digest,
    })
}

pub struct TpmRecoveryJournalBackend<T> {
    transport: T,
    layout: NvRecoveryLayout,
    verified: VerifiedNvRecoveryLayout,
}

impl<T: NvPolicySessionProvider> TpmRecoveryJournalBackend<T> {
    pub fn new(mut transport: T, layout: NvRecoveryLayout) -> Result<Self, NvCounterError> {
        let verified = verify_recovery_layout(&mut transport, layout)?;
        Ok(Self {
            transport,
            layout,
            verified,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn from_verified(
        transport: T,
        layout: NvRecoveryLayout,
        verified: VerifiedNvRecoveryLayout,
    ) -> Self {
        Self {
            transport,
            layout,
            verified,
        }
    }

    fn read_exact<const N: usize>(
        &mut self,
        index: u32,
        name: [u8; 34],
    ) -> Result<[u8; N], NvCounterError> {
        let session = self.transport.authorize_nv(
            index,
            name,
            self.layout.policy_digest,
            NvPolicyOperation::Read,
        )?;
        policy_read(&mut self.transport, index, session)
    }
}

/// Composes the complete protocol stack for an owner-configured TPM recovery
/// journal. Construction first admits all three NV public identities; no
/// journal operation is available when layout or policy admission fails.
pub fn open_recovery_journal<T: TpmTransport, N: TpmNonceSource>(
    mut transport: T,
    nonce_source: N,
    layout: NvRecoveryLayout,
    policy: PcrPolicy,
) -> Result<
    AuthenticatedRecoveryJournal<TpmRecoveryJournalBackend<PcrPolicySessionTransport<T, N>>>,
    NvCounterError,
> {
    if layout.policy_digest != policy.policy_digest {
        return Err(NvCounterError::InvalidIndex);
    }
    let verified = verify_recovery_layout(&mut transport, layout)?;
    let provider = PcrPolicySessionTransport::new(transport, nonce_source, policy, verified);
    let backend = TpmRecoveryJournalBackend::from_verified(provider, layout, verified);
    Ok(AuthenticatedRecoveryJournal::new(backend))
}

// SAFETY: construction validates the exact counter/slot public identities and
// shared owner policy. Every operation obtains a fresh exact-operation session;
// writes are read-verified before return, and counter advancement is checked
// against both the expected predecessor and exact successor.
unsafe impl<T: NvPolicySessionProvider> RecoveryJournalBackend for TpmRecoveryJournalBackend<T> {
    type Error = NvCounterError;

    fn read_counter(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_be_bytes(self.read_exact::<8>(
            self.layout.counter,
            self.verified.counter_name,
        )?))
    }

    fn read_slot(
        &mut self,
        slot: u8,
        output: &mut [u8; RECOVERY_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error> {
        let index = usize::from(slot);
        let handle = *self
            .layout
            .slots
            .get(index)
            .ok_or(NvCounterError::InvalidIndex)?;
        *output = self.read_exact(handle, self.verified.slot_names[index])?;
        Ok(())
    }

    fn write_and_verify_slot(
        &mut self,
        slot: u8,
        input: &[u8; RECOVERY_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error> {
        let index = usize::from(slot);
        let handle = *self
            .layout
            .slots
            .get(index)
            .ok_or(NvCounterError::InvalidIndex)?;
        let name = self.verified.slot_names[index];
        let session = self.transport.authorize_nv(
            handle,
            name,
            self.layout.policy_digest,
            NvPolicyOperation::Write,
        )?;
        policy_write(&mut self.transport, handle, session, input)?;
        if self.read_exact::<RECOVERY_JOURNAL_SLOT_BYTES>(handle, name)? != *input {
            return Err(NvCounterError::Conflict);
        }
        Ok(())
    }

    fn increment_counter(&mut self, expected: u64) -> Result<u64, Self::Error> {
        if self.read_counter()? != expected {
            return Err(NvCounterError::Conflict);
        }
        let session = self.transport.authorize_nv(
            self.layout.counter,
            self.verified.counter_name,
            self.layout.policy_digest,
            NvPolicyOperation::Increment,
        )?;
        policy_increment(&mut self.transport, self.layout.counter, session)?;
        let advanced = self.read_counter()?;
        if expected.checked_add(1) != Some(advanced) {
            return Err(NvCounterError::Conflict);
        }
        Ok(advanced)
    }
}

pub struct TpmReleaseStateJournalBackend<T> {
    transport: T,
    layout: NvReleaseStateLayout,
    verified: VerifiedNvReleaseStateLayout,
}

impl<T: NvPolicySessionProvider> TpmReleaseStateJournalBackend<T> {
    pub fn new(mut transport: T, layout: NvReleaseStateLayout) -> Result<Self, NvCounterError> {
        let verified = verify_release_state_layout(&mut transport, layout)?;
        Ok(Self {
            transport,
            layout,
            verified,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn from_verified(
        transport: T,
        layout: NvReleaseStateLayout,
        verified: VerifiedNvReleaseStateLayout,
    ) -> Self {
        Self {
            transport,
            layout,
            verified,
        }
    }

    fn read_exact<const N: usize>(
        &mut self,
        index: u32,
        name: [u8; 34],
    ) -> Result<[u8; N], NvCounterError> {
        let session = self.transport.authorize_nv(
            index,
            name,
            self.layout.policy_digest,
            NvPolicyOperation::Read,
        )?;
        policy_read(&mut self.transport, index, session)
    }
}

/// Composes the exact policy-session transport and the distinct release-state
/// NV journal. Recovery-authority objects cannot be substituted because their
/// public sizes and admitted Names differ.
pub type PcrReleaseStateJournal<T, N> = AuthenticatedReleaseStateJournal<
    TpmReleaseStateJournalBackend<PcrPolicySessionTransport<T, N, VerifiedNvReleaseStateLayout>>,
>;

pub fn open_release_state_journal<T: TpmTransport, N: TpmNonceSource>(
    mut transport: T,
    nonce_source: N,
    layout: NvReleaseStateLayout,
    policy: PcrPolicy,
) -> Result<PcrReleaseStateJournal<T, N>, NvCounterError> {
    if layout.policy_digest != policy.policy_digest {
        return Err(NvCounterError::InvalidIndex);
    }
    let verified = verify_release_state_layout(&mut transport, layout)?;
    let provider = PcrPolicySessionTransport::new(transport, nonce_source, policy, verified);
    let backend = TpmReleaseStateJournalBackend::from_verified(provider, layout, verified);
    Ok(AuthenticatedReleaseStateJournal::new(backend))
}

// SAFETY: construction admits three distinct, exact-size NV public objects in
// one owner policy. Each operation consumes a fresh exact-operation session;
// writes are read-verified and counter publication checks predecessor and
// exact successor.
unsafe impl<T: NvPolicySessionProvider> ReleaseStateJournalBackend
    for TpmReleaseStateJournalBackend<T>
{
    type Error = NvCounterError;

    fn read_counter(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_be_bytes(self.read_exact::<8>(
            self.layout.counter,
            self.verified.counter_name,
        )?))
    }

    fn read_slot(
        &mut self,
        slot: u8,
        output: &mut [u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error> {
        let index = usize::from(slot);
        let handle = *self
            .layout
            .slots
            .get(index)
            .ok_or(NvCounterError::InvalidIndex)?;
        *output = self.read_exact(handle, self.verified.slot_names[index])?;
        Ok(())
    }

    fn write_and_verify_slot(
        &mut self,
        slot: u8,
        input: &[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error> {
        let index = usize::from(slot);
        let handle = *self
            .layout
            .slots
            .get(index)
            .ok_or(NvCounterError::InvalidIndex)?;
        let name = self.verified.slot_names[index];
        let session = self.transport.authorize_nv(
            handle,
            name,
            self.layout.policy_digest,
            NvPolicyOperation::Write,
        )?;
        policy_write(&mut self.transport, handle, session, input)?;
        if self.read_exact::<RELEASE_STATE_JOURNAL_SLOT_BYTES>(handle, name)? != *input {
            return Err(NvCounterError::Conflict);
        }
        Ok(())
    }

    fn increment_counter(&mut self, expected: u64) -> Result<u64, Self::Error> {
        if self.read_counter()? != expected {
            return Err(NvCounterError::Conflict);
        }
        let session = self.transport.authorize_nv(
            self.layout.counter,
            self.verified.counter_name,
            self.layout.policy_digest,
            NvPolicyOperation::Increment,
        )?;
        policy_increment(&mut self.transport, self.layout.counter, session)?;
        let advanced = self.read_counter()?;
        if expected.checked_add(1) != Some(advanced) {
            return Err(NvCounterError::Conflict);
        }
        Ok(advanced)
    }
}

fn operation_for_command(command: &[u8]) -> Option<NvPolicyOperation> {
    let code = u32::from_be_bytes(command.get(6..10)?.try_into().ok()?);
    match code {
        TPM_CC_NV_READ => Some(NvPolicyOperation::Read),
        TPM_CC_NV_WRITE => Some(NvPolicyOperation::Write),
        TPM_CC_NV_INCREMENT => Some(NvPolicyOperation::Increment),
        _ => None,
    }
}

fn start_policy_session<T: TpmTransport>(
    transport: &mut T,
    nonce: [u8; 32],
) -> Result<u32, NvCounterError> {
    let mut command = [0; 59];
    command[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&59u32.to_be_bytes());
    command[6..10].copy_from_slice(&TPM_CC_START_AUTH_SESSION.to_be_bytes());
    command[10..14].copy_from_slice(&TPM_RH_NULL.to_be_bytes());
    command[14..18].copy_from_slice(&TPM_RH_NULL.to_be_bytes());
    command[18..20].copy_from_slice(&32u16.to_be_bytes());
    command[20..52].copy_from_slice(&nonce);
    command[54] = TPM_SE_POLICY;
    command[55..57].copy_from_slice(&TPM_ALG_NULL.to_be_bytes());
    command[57..59].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let mut response = [0; 64];
    let length = transport.submit(&command, &mut response)?;
    let (tag, _) = response_header(&response[..length])?;
    if tag != TPM_ST_NO_SESSIONS || length != 48 {
        return Err(NvCounterError::MalformedResponse);
    }
    let handle = u32::from_be_bytes(response[10..14].try_into().unwrap());
    if !(0x0300_0000..=0x03ff_ffff).contains(&handle) {
        return Err(NvCounterError::MalformedResponse);
    }
    if u16::from_be_bytes(response[14..16].try_into().unwrap()) != 32
        || response[16..48].iter().all(|byte| *byte == 0)
    {
        let _ = flush_context(transport, handle);
        return Err(NvCounterError::MalformedResponse);
    }
    Ok(handle)
}

fn execute_policy_pcr<T: TpmTransport>(
    transport: &mut T,
    session: u32,
    policy: PcrPolicy,
) -> Result<(), NvCounterError> {
    if !(0x0300_0000..=0x03ff_ffff).contains(&session) {
        return Err(NvCounterError::InvalidSession);
    }
    let mut command = [0; 58];
    command[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&58u32.to_be_bytes());
    command[6..10].copy_from_slice(&TPM_CC_POLICY_PCR.to_be_bytes());
    command[10..14].copy_from_slice(&session.to_be_bytes());
    command[14..16].copy_from_slice(&32u16.to_be_bytes());
    command[16..48].copy_from_slice(&policy.expected_pcr_digest);
    command[48..52].copy_from_slice(&1u32.to_be_bytes());
    command[52..54].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    command[54] = 3;
    command[55..58].copy_from_slice(&policy.pcr_select);
    let mut response = [0; 32];
    let length = transport.submit(&command, &mut response)?;
    parse_empty_no_sessions(&response[..length])
}

fn flush_context<T: TpmTransport>(transport: &mut T, handle: u32) -> Result<(), NvCounterError> {
    let mut command = [0; 14];
    command[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&14u32.to_be_bytes());
    command[6..10].copy_from_slice(&TPM_CC_FLUSH_CONTEXT.to_be_bytes());
    command[10..14].copy_from_slice(&handle.to_be_bytes());
    let mut response = [0; 32];
    let length = transport.submit(&command, &mut response)?;
    parse_empty_no_sessions(&response[..length])
}

fn parse_empty_no_sessions(response: &[u8]) -> Result<(), NvCounterError> {
    let (tag, _) = response_header(response)?;
    if tag == TPM_ST_NO_SESSIONS && response.len() == 10 {
        Ok(())
    } else {
        Err(NvCounterError::MalformedResponse)
    }
}

fn policy_read<T: TpmTransport, const N: usize>(
    transport: &mut T,
    index: u32,
    session: AuthorizedNvSession,
) -> Result<[u8; N], NvCounterError> {
    if N == 0 || N > RELEASE_STATE_JOURNAL_SLOT_BYTES {
        return Err(NvCounterError::InvalidIndex);
    }
    let mut command = [0; 35];
    sessions_header(&mut command, TPM_CC_NV_READ);
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    encode_policy_authorization(&mut command[18..31], session)?;
    command[31..33].copy_from_slice(&(N as u16).to_be_bytes());
    let mut response = [0; 256];
    let length = transport.submit(&command, &mut response)?;
    let parameters = parse_policy_response(&response[..length])?;
    if parameters.len() != N + 2
        || u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize != N
    {
        return Err(NvCounterError::MalformedResponse);
    }
    parameters[2..]
        .try_into()
        .map_err(|_| NvCounterError::MalformedResponse)
}

fn policy_write<T: TpmTransport, const N: usize>(
    transport: &mut T,
    index: u32,
    session: AuthorizedNvSession,
    input: &[u8; N],
) -> Result<(), NvCounterError> {
    if N == 0 || N > RELEASE_STATE_JOURNAL_SLOT_BYTES {
        return Err(NvCounterError::InvalidIndex);
    }
    let mut command = [0; 35 + RELEASE_STATE_JOURNAL_SLOT_BYTES];
    sessions_header(&mut command, TPM_CC_NV_WRITE);
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    encode_policy_authorization(&mut command[18..31], session)?;
    command[2..6].copy_from_slice(&((35 + N) as u32).to_be_bytes());
    command[31..33].copy_from_slice(&(N as u16).to_be_bytes());
    command[33..33 + N].copy_from_slice(input);
    let mut response = [0; 96];
    let length = transport.submit(&command[..35 + N], &mut response)?;
    if !parse_policy_response(&response[..length])?.is_empty() {
        return Err(NvCounterError::MalformedResponse);
    }
    Ok(())
}

fn policy_increment<T: TpmTransport>(
    transport: &mut T,
    index: u32,
    session: AuthorizedNvSession,
) -> Result<(), NvCounterError> {
    let mut command = [0; 31];
    sessions_header(&mut command, TPM_CC_NV_INCREMENT);
    command[10..14].copy_from_slice(&index.to_be_bytes());
    command[14..18].copy_from_slice(&index.to_be_bytes());
    encode_policy_authorization(&mut command[18..31], session)?;
    let mut response = [0; 96];
    let length = transport.submit(&command, &mut response)?;
    if !parse_policy_response(&response[..length])?.is_empty() {
        return Err(NvCounterError::MalformedResponse);
    }
    Ok(())
}

fn encode_policy_authorization(
    output: &mut [u8],
    session: AuthorizedNvSession,
) -> Result<(), NvCounterError> {
    if output.len() != 13 || !(0x0300_0000..=0x03ff_ffff).contains(&session.handle) {
        return Err(NvCounterError::InvalidSession);
    }
    output.fill(0);
    output[..4].copy_from_slice(&9u32.to_be_bytes());
    output[4..8].copy_from_slice(&session.handle.to_be_bytes());
    Ok(())
}

fn parse_policy_response(response: &[u8]) -> Result<&[u8], NvCounterError> {
    let (tag, _) = response_header(response)?;
    if tag != TPM_ST_SESSIONS || response.len() < 19 {
        return Err(NvCounterError::MalformedResponse);
    }
    let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
    let parameter_end = 14usize
        .checked_add(parameter_size)
        .ok_or(NvCounterError::MalformedResponse)?;
    if parameter_end + 5 > response.len() {
        return Err(NvCounterError::MalformedResponse);
    }
    let auth = &response[parameter_end..];
    let nonce_size = u16::from_be_bytes(auth[..2].try_into().unwrap()) as usize;
    let attributes_at = 2usize
        .checked_add(nonce_size)
        .ok_or(NvCounterError::MalformedResponse)?;
    if nonce_size > 32 || attributes_at + 3 != auth.len() || auth[attributes_at] != 0 {
        return Err(NvCounterError::MalformedResponse);
    }
    if u16::from_be_bytes(auth[attributes_at + 1..].try_into().unwrap()) != 0 {
        return Err(NvCounterError::MalformedResponse);
    }
    Ok(&response[14..parameter_end])
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
    use mrml_crypto::Sha3_256;
    use mrml_kernel::{BOOTSTRAP_STATE_BYTES, BootstrapState, MonotonicStateStore};
    use mrml_storage::{AUTHORITY_RECOVERY_STATE_BYTES, AuthorityRecoveryStateStore};

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

    fn policy_response(response: &mut [u8], parameters: &[u8]) -> usize {
        let length = 14 + parameters.len() + 5;
        response[..length].fill(0);
        response[..2].copy_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        response[2..6].copy_from_slice(&(length as u32).to_be_bytes());
        response[10..14].copy_from_slice(&(parameters.len() as u32).to_be_bytes());
        response[14..14 + parameters.len()].copy_from_slice(parameters);
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
                    RECOVERY_JOURNAL_SLOT_BYTES as u16
                },
                self.corrupt_name,
            ))
        }
    }

    fn layout(policy: [u8; 32]) -> NvRecoveryLayout {
        NvRecoveryLayout::new(0x0180_0010, [0x0180_0011, 0x0180_0012], policy).unwrap()
    }

    struct ReleaseLayoutTransport {
        policy: [u8; 32],
        slot_size: u16,
    }

    impl TpmTransport for ReleaseLayoutTransport {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            if u32::from_be_bytes(command[6..10].try_into().unwrap()) != TPM_CC_NV_READ_PUBLIC {
                return Err(NvCounterError::Transport);
            }
            let index = u32::from_be_bytes(command[10..14].try_into().unwrap());
            let counter = index == 0x0180_0020;
            Ok(public_response(
                response,
                index,
                TPMA_NV_POLICYWRITE
                    | TPMA_NV_POLICYREAD
                    | TPMA_NV_NO_DA
                    | if counter {
                        TPMA_NV_COUNTER
                    } else {
                        TPMA_NV_WRITEALL
                    },
                &self.policy,
                if counter { 8 } else { self.slot_size },
                false,
            ))
        }
    }

    fn release_layout(policy: [u8; 32]) -> NvReleaseStateLayout {
        NvReleaseStateLayout::new(0x0180_0020, [0x0180_0021, 0x0180_0022], policy).unwrap()
    }

    #[test]
    fn release_layout_is_distinct_and_requires_exact_public_objects() {
        let policy = [0x6d; 32];
        let mut transport = ReleaseLayoutTransport {
            policy,
            slot_size: RELEASE_STATE_JOURNAL_SLOT_BYTES as u16,
        };
        let verified = verify_release_state_layout(&mut transport, release_layout(policy)).unwrap();
        assert_ne!(verified.counter_name(), verified.slot_names()[0]);
        assert_ne!(verified.slot_names()[0], verified.slot_names()[1]);

        transport.slot_size = RECOVERY_JOURNAL_SLOT_BYTES as u16;
        assert_eq!(
            verify_release_state_layout(&mut transport, release_layout(policy)),
            Err(NvCounterError::InvalidIndex)
        );
        assert_eq!(
            NvReleaseStateLayout::new(0x0180_0020, [0x0180_0020, 0x0180_0022], policy),
            Err(NvCounterError::InvalidIndex)
        );
        assert_eq!(
            verify_distinct_journal_layouts(layout(policy), release_layout(policy)),
            Ok(())
        );
        let aliased =
            NvReleaseStateLayout::new(0x0180_0020, [0x0180_0012, 0x0180_0022], policy).unwrap();
        assert_eq!(
            verify_distinct_journal_layouts(layout(policy), aliased),
            Err(NvCounterError::InvalidIndex)
        );
    }

    #[test]
    fn recovery_configuration_requires_exact_canonical_fields() {
        let policy = [b'a'; 64];
        let pcr_digest = [b'B'; 64];
        let configuration = RecoveryJournalConfiguration::parse(
            b"01800010",
            b"01800011",
            b"01800012",
            &policy,
            &pcr_digest,
            b"000800",
        )
        .unwrap();
        assert_eq!(
            configuration.into_parts(),
            (
                layout([0xaa; 32]),
                PcrPolicy::new([0xaa; 32], [0xbb; 32], [0, 8, 0]).unwrap(),
            )
        );
        assert_eq!(
            RecoveryJournalConfiguration::parse_optional([None; 6]),
            Ok(None)
        );
        assert!(matches!(
            RecoveryJournalConfiguration::parse_optional([
                Some(&b"01800010"[..]),
                None,
                Some(&b"01800012"[..]),
                Some(&policy),
                Some(&pcr_digest),
                Some(&b"000800"[..]),
            ]),
            Err(NvCounterError::InvalidIndex)
        ));

        for malformed in [
            &b"0180001"[..],
            &b"018000100"[..],
            &b"0180001g"[..],
            &b"00000000"[..],
        ] {
            assert!(matches!(
                RecoveryJournalConfiguration::parse(
                    malformed,
                    b"01800011",
                    b"01800012",
                    &policy,
                    &pcr_digest,
                    b"000800",
                ),
                Err(NvCounterError::InvalidIndex)
            ));
        }
        assert!(matches!(
            RecoveryJournalConfiguration::parse(
                b"01800010",
                b"01800010",
                b"01800012",
                &policy,
                &pcr_digest,
                b"000800",
            ),
            Err(NvCounterError::InvalidIndex)
        ));
        assert!(matches!(
            RecoveryJournalConfiguration::parse(
                b"01800010",
                b"01800011",
                b"01800012",
                &[b'0'; 64],
                &pcr_digest,
                b"000800",
            ),
            Err(NvCounterError::InvalidIndex)
        ));
        assert!(matches!(
            RecoveryJournalConfiguration::parse(
                b"01800010",
                b"01800011",
                b"01800012",
                &policy,
                &pcr_digest,
                b"000000",
            ),
            Err(NvCounterError::InvalidSession)
        ));
    }

    #[test]
    fn release_configuration_requires_complete_distinct_fields() {
        let policy = [b'6'; 64];
        let pcr_digest = [b'7'; 64];
        let configuration = ReleaseStateJournalConfiguration::parse(
            b"01800020",
            b"01800021",
            b"01800022",
            &policy,
            &pcr_digest,
            b"000800",
        )
        .unwrap();
        assert_eq!(
            configuration.into_parts(),
            (
                release_layout([0x66; 32]),
                PcrPolicy::new([0x66; 32], [0x77; 32], [0, 8, 0]).unwrap(),
            )
        );
        assert_eq!(
            ReleaseStateJournalConfiguration::parse_optional([None; 6]),
            Ok(None)
        );
        assert!(matches!(
            ReleaseStateJournalConfiguration::parse_optional([
                Some(&b"01800020"[..]),
                Some(&b"01800021"[..]),
                None,
                Some(&policy),
                Some(&pcr_digest),
                Some(&b"000800"[..]),
            ]),
            Err(NvCounterError::InvalidIndex)
        ));
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

    struct JournalTransport {
        policy: [u8; 32],
        counter: u64,
        slots: [[u8; RECOVERY_JOURNAL_SLOT_BYTES]; 2],
        next_session: u32,
        pending: Option<(u32, u32, NvPolicyOperation)>,
        authorizations: usize,
        corrupt_readback: bool,
        concrete_sessions: bool,
        policy_calls: usize,
        flushes: usize,
    }

    impl JournalTransport {
        fn new(policy: [u8; 32]) -> Self {
            Self {
                policy,
                counter: 0,
                slots: [[0; RECOVERY_JOURNAL_SLOT_BYTES]; 2],
                next_session: 0x0300_0001,
                pending: None,
                authorizations: 0,
                corrupt_readback: false,
                concrete_sessions: false,
                policy_calls: 0,
                flushes: 0,
            }
        }

        fn new_concrete(policy: [u8; 32]) -> Self {
            Self {
                concrete_sessions: true,
                ..Self::new(policy)
            }
        }

        fn index_kind(index: u32) -> Option<(u32, u16)> {
            match index {
                0x0180_0010 => Some((TPMA_NV_COUNTER, 8)),
                0x0180_0011 | 0x0180_0012 => {
                    Some((TPMA_NV_WRITEALL, RECOVERY_JOURNAL_SLOT_BYTES as u16))
                }
                _ => None,
            }
        }

        fn expected_name(&self, index: u32) -> Option<[u8; 34]> {
            let (kind, size) = Self::index_kind(index)?;
            let mut response = [0; 128];
            let length = public_response(
                &mut response,
                index,
                TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA | kind,
                &self.policy,
                size,
                false,
            );
            response[length - 34..length].try_into().ok()
        }

        fn consume_session(
            &mut self,
            command: &[u8],
            operation: NvPolicyOperation,
        ) -> Result<(), NvCounterError> {
            if self.concrete_sessions {
                return Ok(());
            }
            let handle = u32::from_be_bytes(command[22..26].try_into().unwrap());
            let index = u32::from_be_bytes(command[14..18].try_into().unwrap());
            if self.pending.take() != Some((handle, index, operation)) {
                return Err(NvCounterError::InvalidSession);
            }
            Ok(())
        }
    }

    impl TpmTransport for JournalTransport {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
            let index = u32::from_be_bytes(command[10..14].try_into().unwrap());
            if code == TPM_CC_START_AUTH_SESSION {
                if !self.concrete_sessions {
                    return Err(NvCounterError::Transport);
                }
                let handle = self.next_session;
                self.next_session += 1;
                response[..48].fill(0);
                response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                response[2..6].copy_from_slice(&48u32.to_be_bytes());
                response[10..14].copy_from_slice(&handle.to_be_bytes());
                response[14..16].copy_from_slice(&32u16.to_be_bytes());
                response[16..48].fill(0x91);
                self.authorizations += 1;
                return Ok(48);
            }
            if code == TPM_CC_POLICY_PCR {
                self.policy_calls += 1;
                response[..10].fill(0);
                response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                response[2..6].copy_from_slice(&10u32.to_be_bytes());
                return Ok(10);
            }
            if code == TPM_CC_FLUSH_CONTEXT {
                self.flushes += 1;
                response[..10].fill(0);
                response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                response[2..6].copy_from_slice(&10u32.to_be_bytes());
                return Ok(10);
            }
            if code == TPM_CC_NV_READ_PUBLIC {
                let (kind, size) = Self::index_kind(index).ok_or(NvCounterError::InvalidIndex)?;
                return Ok(public_response(
                    response,
                    index,
                    TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA | kind,
                    &self.policy,
                    size,
                    false,
                ));
            }
            match code {
                TPM_CC_NV_READ => {
                    self.consume_session(command, NvPolicyOperation::Read)?;
                    let size = u16::from_be_bytes(command[31..33].try_into().unwrap()) as usize;
                    let mut parameters = [0; 2 + RECOVERY_JOURNAL_SLOT_BYTES];
                    parameters[..2].copy_from_slice(&(size as u16).to_be_bytes());
                    if index == 0x0180_0010 {
                        parameters[2..10].copy_from_slice(&self.counter.to_be_bytes());
                    } else {
                        let slot = usize::from(index == 0x0180_0012);
                        parameters[2..2 + size].copy_from_slice(&self.slots[slot][..size]);
                        if self.corrupt_readback {
                            parameters[2] ^= 1;
                        }
                    }
                    Ok(policy_response(response, &parameters[..2 + size]))
                }
                TPM_CC_NV_WRITE => {
                    self.consume_session(command, NvPolicyOperation::Write)?;
                    let slot = usize::from(index == 0x0180_0012);
                    self.slots[slot]
                        .copy_from_slice(&command[33..33 + RECOVERY_JOURNAL_SLOT_BYTES]);
                    Ok(policy_response(response, &[]))
                }
                TPM_CC_NV_INCREMENT => {
                    self.consume_session(command, NvPolicyOperation::Increment)?;
                    self.counter = self
                        .counter
                        .checked_add(1)
                        .ok_or(NvCounterError::Conflict)?;
                    Ok(policy_response(response, &[]))
                }
                _ => Err(NvCounterError::Transport),
            }
        }
    }

    // SAFETY: the mock issues a unique one-use session and checks that the next
    // exact command consumes it with the requested operation.
    unsafe impl NvPolicySessionProvider for JournalTransport {
        fn authorize_nv(
            &mut self,
            index: u32,
            name: [u8; 34],
            policy_digest: [u8; 32],
            operation: NvPolicyOperation,
        ) -> Result<AuthorizedNvSession, NvCounterError> {
            if policy_digest != self.policy
                || self.pending.is_some()
                || self.expected_name(index) != Some(name)
            {
                return Err(NvCounterError::InvalidSession);
            }
            let handle = self.next_session;
            self.next_session += 1;
            self.pending = Some((handle, index, operation));
            self.authorizations += 1;
            Ok(unsafe { AuthorizedNvSession::from_satisfied_policy(handle) })
        }
    }

    struct ReleaseJournalTransport {
        policy: [u8; 32],
        counter: u64,
        slots: [[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES]; 2],
        next_session: u32,
        pending: Option<(u32, u32, NvPolicyOperation)>,
    }

    impl ReleaseJournalTransport {
        fn new(policy: [u8; 32], initial: [u8; BOOTSTRAP_STATE_BYTES]) -> Self {
            let mut slots = [[0; RELEASE_STATE_JOURNAL_SLOT_BYTES]; 2];
            slots[0][..8].copy_from_slice(b"MRLSTJ01");
            slots[0][16..16 + BOOTSTRAP_STATE_BYTES].copy_from_slice(&initial);
            let digest = Sha3_256::digest(&slots[0][..16 + BOOTSTRAP_STATE_BYTES]);
            slots[0][16 + BOOTSTRAP_STATE_BYTES..].copy_from_slice(&digest);
            Self {
                policy,
                counter: 0,
                slots,
                next_session: 0x0300_0001,
                pending: None,
            }
        }

        fn expected_name(&self, index: u32) -> Option<[u8; 34]> {
            let (kind, size) = match index {
                0x0180_0020 => (TPMA_NV_COUNTER, 8),
                0x0180_0021 | 0x0180_0022 => {
                    (TPMA_NV_WRITEALL, RELEASE_STATE_JOURNAL_SLOT_BYTES as u16)
                }
                _ => return None,
            };
            let mut response = [0; 192];
            let length = public_response(
                &mut response,
                index,
                TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA | kind,
                &self.policy,
                size,
                false,
            );
            response[length - 34..length].try_into().ok()
        }

        fn consume(
            &mut self,
            command: &[u8],
            operation: NvPolicyOperation,
        ) -> Result<(), NvCounterError> {
            let handle = u32::from_be_bytes(command[22..26].try_into().unwrap());
            let index = u32::from_be_bytes(command[14..18].try_into().unwrap());
            if self.pending.take() != Some((handle, index, operation)) {
                return Err(NvCounterError::InvalidSession);
            }
            Ok(())
        }
    }

    impl TpmTransport for ReleaseJournalTransport {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
            let index = u32::from_be_bytes(command[10..14].try_into().unwrap());
            if code == TPM_CC_NV_READ_PUBLIC {
                let (kind, size) = match index {
                    0x0180_0020 => (TPMA_NV_COUNTER, 8),
                    0x0180_0021 | 0x0180_0022 => {
                        (TPMA_NV_WRITEALL, RELEASE_STATE_JOURNAL_SLOT_BYTES as u16)
                    }
                    _ => return Err(NvCounterError::InvalidIndex),
                };
                return Ok(public_response(
                    response,
                    index,
                    TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA | kind,
                    &self.policy,
                    size,
                    false,
                ));
            }
            match code {
                TPM_CC_NV_READ => {
                    self.consume(command, NvPolicyOperation::Read)?;
                    let size = u16::from_be_bytes(command[31..33].try_into().unwrap()) as usize;
                    let mut parameters = [0; 2 + RELEASE_STATE_JOURNAL_SLOT_BYTES];
                    parameters[..2].copy_from_slice(&(size as u16).to_be_bytes());
                    if index == 0x0180_0020 {
                        parameters[2..10].copy_from_slice(&self.counter.to_be_bytes());
                    } else {
                        let slot = usize::from(index == 0x0180_0022);
                        parameters[2..2 + size].copy_from_slice(&self.slots[slot][..size]);
                    }
                    Ok(policy_response(response, &parameters[..2 + size]))
                }
                TPM_CC_NV_WRITE => {
                    self.consume(command, NvPolicyOperation::Write)?;
                    let size = u16::from_be_bytes(command[31..33].try_into().unwrap()) as usize;
                    if size != RELEASE_STATE_JOURNAL_SLOT_BYTES || command.len() != 35 + size {
                        return Err(NvCounterError::InvalidIndex);
                    }
                    let slot = usize::from(index == 0x0180_0022);
                    self.slots[slot].copy_from_slice(&command[33..33 + size]);
                    Ok(policy_response(response, &[]))
                }
                TPM_CC_NV_INCREMENT => {
                    self.consume(command, NvPolicyOperation::Increment)?;
                    self.counter = self
                        .counter
                        .checked_add(1)
                        .ok_or(NvCounterError::Conflict)?;
                    Ok(policy_response(response, &[]))
                }
                _ => Err(NvCounterError::Transport),
            }
        }
    }

    // SAFETY: the mock admits the exact verified Name and consumes each unique
    // session on the immediately following exact NV operation.
    unsafe impl NvPolicySessionProvider for ReleaseJournalTransport {
        fn authorize_nv(
            &mut self,
            index: u32,
            name: [u8; 34],
            policy_digest: [u8; 32],
            operation: NvPolicyOperation,
        ) -> Result<AuthorizedNvSession, NvCounterError> {
            if self.pending.is_some()
                || policy_digest != self.policy
                || self.expected_name(index) != Some(name)
            {
                return Err(NvCounterError::InvalidSession);
            }
            let handle = self.next_session;
            self.next_session += 1;
            self.pending = Some((handle, index, operation));
            Ok(unsafe { AuthorizedNvSession::from_satisfied_policy(handle) })
        }
    }

    #[test]
    fn release_backend_publishes_exact_bootstrap_state_through_200_byte_objects() {
        let policy = [0x6d; 32];
        let original = BootstrapState::genesis([0x31; 64], 7).unwrap().encode();
        let replacement = BootstrapState::genesis([0x52; 64], 8).unwrap().encode();
        let backend = TpmReleaseStateJournalBackend::new(
            ReleaseJournalTransport::new(policy, original),
            release_layout(policy),
        )
        .unwrap();
        let mut journal = AuthenticatedReleaseStateJournal::new(backend);
        journal.compare_and_store(&original, &replacement).unwrap();
        let mut loaded = [0; BOOTSTRAP_STATE_BYTES];
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, replacement);
        let transport = journal.into_backend().into_transport();
        assert_eq!(transport.counter, 1);
        assert!(transport.pending.is_none());
    }

    #[test]
    fn policy_backend_uses_fresh_exact_sessions_and_read_verifies_writes() {
        let policy = [0x7c; 32];
        let mut backend =
            TpmRecoveryJournalBackend::new(JournalTransport::new(policy), layout(policy)).unwrap();
        assert_eq!(backend.read_counter(), Ok(0));
        let successor = [0xa5; RECOVERY_JOURNAL_SLOT_BYTES];
        assert_eq!(backend.write_and_verify_slot(1, &successor), Ok(()));
        assert_eq!(backend.increment_counter(0), Ok(1));
        let transport = backend.into_transport();
        assert_eq!(transport.slots[1], successor);
        assert_eq!(transport.authorizations, 6);
        assert!(transport.pending.is_none());

        let mut transport = JournalTransport::new(policy);
        transport.corrupt_readback = true;
        let mut backend = TpmRecoveryJournalBackend::new(transport, layout(policy)).unwrap();
        assert_eq!(
            backend.write_and_verify_slot(0, &successor),
            Err(NvCounterError::Conflict)
        );
        assert_eq!(backend.increment_counter(1), Err(NvCounterError::Conflict));
    }

    fn encoded_journal_slot(
        sequence: u64,
        state: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> [u8; RECOVERY_JOURNAL_SLOT_BYTES] {
        let mut slot = [0; RECOVERY_JOURNAL_SLOT_BYTES];
        slot[..8].copy_from_slice(b"MRJRNL01");
        slot[8..16].copy_from_slice(&sequence.to_le_bytes());
        slot[16..80].copy_from_slice(state);
        let mut digest = Sha3_256::new();
        digest.update(&slot[..80]);
        slot[80..].copy_from_slice(&digest.finalize());
        slot
    }

    #[test]
    fn composed_policy_journal_admits_layout_and_atomically_replaces_state() {
        let policy_digest = [0x7c; 32];
        let original = [0x31; AUTHORITY_RECOVERY_STATE_BYTES];
        let replacement = [0x52; AUTHORITY_RECOVERY_STATE_BYTES];
        let mut transport = JournalTransport::new_concrete(policy_digest);
        transport.slots[0] = encoded_journal_slot(0, &original);
        let mut journal = open_recovery_journal(
            transport,
            CounterNonce { next: 1 },
            layout(policy_digest),
            PcrPolicy::new(policy_digest, [0xb4; 32], [0, 8, 0]).unwrap(),
        )
        .unwrap();

        let mut loaded = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, original);
        journal.compare_and_store(&original, &replacement).unwrap();
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, replacement);

        let provider = journal.into_backend().into_transport();
        assert!(provider.pending.is_none());
        let (transport, _) = provider.into_parts();
        assert_eq!(transport.counter, 1);
        assert_eq!(transport.policy_calls, transport.authorizations);
        assert_eq!(transport.flushes, 0);
        assert_eq!(transport.authorizations, 13);

        assert!(matches!(
            open_recovery_journal(
                JournalTransport::new_concrete([0x99; 32]),
                CounterNonce { next: 1 },
                layout([0x99; 32]),
                PcrPolicy::new(policy_digest, [0xb4; 32], [0, 8, 0]).unwrap(),
            ),
            Err(NvCounterError::InvalidIndex)
        ));
    }

    #[test]
    fn policy_commands_reject_forged_sessions_and_malformed_auth_responses() {
        let invalid = unsafe { AuthorizedNvSession::from_satisfied_policy(1) };
        let mut transport = JournalTransport::new([1; 32]);
        assert_eq!(
            policy_read::<_, 8>(&mut transport, 0x0180_0010, invalid),
            Err(NvCounterError::InvalidSession)
        );
        let mut malformed = [0; 19];
        policy_response(&mut malformed, &[]);
        malformed[16] = 1;
        assert_eq!(
            parse_policy_response(&malformed),
            Err(NvCounterError::MalformedResponse)
        );
    }

    struct Nonce {
        value: [u8; 32],
    }

    impl TpmNonceSource for Nonce {
        fn fill_nonce(&mut self, output: &mut [u8; 32]) -> Result<(), NvCounterError> {
            *output = self.value;
            Ok(())
        }
    }

    struct CounterNonce {
        next: u8,
    }

    impl TpmNonceSource for CounterNonce {
        fn fill_nonce(&mut self, output: &mut [u8; 32]) -> Result<(), NvCounterError> {
            output.fill(self.next);
            self.next = self
                .next
                .checked_add(1)
                .ok_or(NvCounterError::InvalidSession)?;
            Ok(())
        }
    }

    struct PolicyTpm {
        policy_error: bool,
        malformed_start: bool,
        nv_error: bool,
        flushes: usize,
        policy_calls: usize,
    }

    impl TpmTransport for PolicyTpm {
        fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
            let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
            match code {
                TPM_CC_START_AUTH_SESSION => {
                    assert_eq!(command.len(), 59);
                    assert_eq!(&command[10..18], &[0x40, 0, 0, 7, 0x40, 0, 0, 7]);
                    assert_eq!(u16::from_be_bytes(command[18..20].try_into().unwrap()), 32);
                    response[..48].fill(0);
                    response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                    response[2..6].copy_from_slice(&48u32.to_be_bytes());
                    response[10..14].copy_from_slice(&0x0300_0010u32.to_be_bytes());
                    response[14..16].copy_from_slice(&32u16.to_be_bytes());
                    response[16..48].fill(0x44);
                    if self.malformed_start {
                        response[14..16].copy_from_slice(&31u16.to_be_bytes());
                    }
                    Ok(48)
                }
                TPM_CC_POLICY_PCR => {
                    self.policy_calls += 1;
                    assert_eq!(command.len(), 58);
                    assert_eq!(command[54], 3);
                    if self.policy_error {
                        return Err(NvCounterError::Transport);
                    }
                    response[..10].fill(0);
                    response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                    response[2..6].copy_from_slice(&10u32.to_be_bytes());
                    Ok(10)
                }
                TPM_CC_FLUSH_CONTEXT => {
                    self.flushes += 1;
                    response[..10].fill(0);
                    response[..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
                    response[2..6].copy_from_slice(&10u32.to_be_bytes());
                    Ok(10)
                }
                TPM_CC_NV_INCREMENT => {
                    if self.nv_error {
                        return Err(NvCounterError::Transport);
                    }
                    Ok(policy_response(response, &[]))
                }
                _ => Err(NvCounterError::Transport),
            }
        }
    }

    fn pcr_policy() -> PcrPolicy {
        PcrPolicy::new([0x33; 32], [0x55; 32], [1, 0, 0]).unwrap()
    }

    fn policy_name() -> [u8; 34] {
        let mut name = [0x0b; 34];
        name[..2].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        name
    }

    fn verified_policy_layout() -> VerifiedNvRecoveryLayout {
        let counter_name = policy_name();
        let mut first_name = counter_name;
        first_name[2] ^= 1;
        let mut second_name = counter_name;
        second_name[2] ^= 2;
        VerifiedNvRecoveryLayout {
            counter: 0x0180_0010,
            counter_name,
            slots: [0x0180_0011, 0x0180_0012],
            slot_names: [first_name, second_name],
            policy_digest: [0x33; 32],
        }
    }

    #[test]
    fn pcr_provider_issues_one_fresh_session_for_exact_next_operation() {
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: false,
            nv_error: false,
            flushes: 0,
            policy_calls: 0,
        };
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [0x22; 32] },
            pcr_policy(),
            verified_policy_layout(),
        );
        let name = policy_name();
        let session = provider
            .authorize_nv(0x0180_0010, name, [0x33; 32], NvPolicyOperation::Increment)
            .unwrap();
        assert!(matches!(
            provider.authorize_nv(0x0180_0010, name, [0x33; 32], NvPolicyOperation::Increment,),
            Err(NvCounterError::InvalidSession)
        ));
        assert_eq!(
            policy_increment(&mut provider, 0x0180_0010, session),
            Ok(())
        );
        let (tpm, _) = provider.into_parts();
        assert_eq!(tpm.policy_calls, 1);
        assert_eq!(tpm.flushes, 0);
    }

    #[test]
    fn pcr_provider_rejects_index_substitution_in_either_command_handle() {
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: false,
            nv_error: false,
            flushes: 0,
            policy_calls: 0,
        };
        let verified = verified_policy_layout();
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [0x55; 32] },
            pcr_policy(),
            verified,
        );

        assert!(matches!(
            provider.authorize_nv(
                0x0180_0010,
                verified.slot_names[0],
                [0x33; 32],
                NvPolicyOperation::Read,
            ),
            Err(NvCounterError::InvalidSession)
        ));
        assert!(matches!(
            provider.authorize_nv(
                0x0180_0013,
                verified.counter_name,
                [0x33; 32],
                NvPolicyOperation::Read,
            ),
            Err(NvCounterError::InvalidSession)
        ));
        assert_eq!(provider.transport.policy_calls, 0);

        for (authorization_index, nv_index) in [
            (0x0180_0011u32, 0x0180_0010u32),
            (0x0180_0010u32, 0x0180_0011u32),
        ] {
            let session = provider
                .authorize_nv(
                    0x0180_0010,
                    policy_name(),
                    [0x33; 32],
                    NvPolicyOperation::Read,
                )
                .unwrap();
            let mut command = [0; 35];
            sessions_header(&mut command, TPM_CC_NV_READ);
            command[10..14].copy_from_slice(&authorization_index.to_be_bytes());
            command[14..18].copy_from_slice(&nv_index.to_be_bytes());
            encode_policy_authorization(&mut command[18..31], session).unwrap();
            command[31..33].copy_from_slice(&8u16.to_be_bytes());
            let mut response = [0; 32];

            assert_eq!(
                provider.submit(&command, &mut response),
                Err(NvCounterError::InvalidSession)
            );
            provider.nonce_source.value[0] = provider.nonce_source.value[0].wrapping_add(1);
        }

        assert_eq!(provider.transport.flushes, 2);
        assert!(provider.pending.is_none());
    }

    #[test]
    fn pcr_provider_flushes_session_after_ambiguous_nv_transport_failure() {
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: false,
            nv_error: true,
            flushes: 0,
            policy_calls: 0,
        };
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [0x44; 32] },
            pcr_policy(),
            verified_policy_layout(),
        );
        let session = provider
            .authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Increment,
            )
            .unwrap();

        assert_eq!(
            policy_increment(&mut provider, 0x0180_0010, session),
            Err(NvCounterError::Transport)
        );
        assert_eq!(provider.transport.flushes, 1);
        assert!(provider.pending.is_none());
    }

    #[test]
    fn pcr_provider_rejects_bad_entropy_policy_and_command_use() {
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: false,
            nv_error: false,
            flushes: 0,
            policy_calls: 0,
        };
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [0; 32] },
            pcr_policy(),
            verified_policy_layout(),
        );
        assert!(matches!(
            provider.authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Read,
            ),
            Err(NvCounterError::InvalidSession)
        ));

        provider.nonce_source.value = [1; 32];
        let session = provider
            .authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Read,
            )
            .unwrap();
        assert_eq!(
            policy_increment(&mut provider, 0x0180_0010, session),
            Err(NvCounterError::InvalidSession)
        );
        assert_eq!(provider.transport.flushes, 1);

        provider.transport.policy_error = true;
        provider.nonce_source.value = [2; 32];
        assert!(matches!(
            provider.authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Read,
            ),
            Err(NvCounterError::Transport)
        ));
        assert_eq!(provider.transport.flushes, 2);
    }

    #[test]
    fn pcr_provider_rejects_reused_nonzero_nonce() {
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: false,
            nv_error: false,
            flushes: 0,
            policy_calls: 0,
        };
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [7; 32] },
            pcr_policy(),
            verified_policy_layout(),
        );
        let session = provider
            .authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Increment,
            )
            .unwrap();
        policy_increment(&mut provider, 0x0180_0010, session).unwrap();
        assert!(matches!(
            provider.authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Increment,
            ),
            Err(NvCounterError::InvalidSession)
        ));
    }

    #[test]
    fn pcr_provider_rejects_malformed_start_response_and_recipe() {
        assert_eq!(
            PcrPolicy::new([0; 32], [1; 32], [1, 0, 0]),
            Err(NvCounterError::InvalidSession)
        );
        let tpm = PolicyTpm {
            policy_error: false,
            malformed_start: true,
            nv_error: false,
            flushes: 0,
            policy_calls: 0,
        };
        let mut provider = PcrPolicySessionTransport::new(
            tpm,
            Nonce { value: [1; 32] },
            pcr_policy(),
            verified_policy_layout(),
        );
        assert!(matches!(
            provider.authorize_nv(
                0x0180_0010,
                policy_name(),
                [0x33; 32],
                NvPolicyOperation::Read,
            ),
            Err(NvCounterError::MalformedResponse)
        ));
        assert_eq!(provider.transport.flushes, 1);
    }
}
