#![no_std]

//! Fixed-capacity policy/configuration service foundation.
//!
//! Setting identifiers select records; they never authorize access. Every
//! read and transaction update repeats exact capability checks against the
//! schema-bound object. Transactions preflight all schema, authority, revision,
//! capacity, and sequence conditions before the first mutation.

use core::array;

use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, Message, ObjectId, Priority, Rights, ServiceId,
    ServiceState, ServiceSupervisor, TaskRuntime,
};

pub const MAX_CONFIG_VALUE_BYTES: usize = 64;
pub const MAX_WIRE_UPDATES: usize = 4;
pub const CONFIG_REQUEST_HEADER_BYTES: usize = 48;
pub const CONFIG_UPDATE_BYTES: usize = 80;
pub const MAX_CONFIG_REQUEST_BYTES: usize =
    CONFIG_REQUEST_HEADER_BYTES + MAX_WIRE_UPDATES * CONFIG_UPDATE_BYTES;
pub const CONFIG_RESPONSE_BYTES: usize = 112;
pub const SUPERVISION_REQUEST_BYTES: usize = 48;
pub const SUPERVISION_RESPONSE_BYTES: usize = 48;
pub const SYSTEM_PROTOCOL_VERSION: u16 = 1;

const CONFIG_REQUEST_MAGIC: [u8; 4] = *b"MRCQ";
const CONFIG_RESPONSE_MAGIC: [u8; 4] = *b"MRCP";
const SUPERVISION_REQUEST_MAGIC: [u8; 4] = *b"MRSQ";
const SUPERVISION_RESPONSE_MAGIC: [u8; 4] = *b"MRSP";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingId(u32);

impl SettingId {
    pub const fn new(value: u32) -> Result<Self, ConfigError> {
        if value == 0 {
            return Err(ConfigError::InvalidSetting);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValueKind {
    Bool = 1,
    U64 = 2,
    Bytes = 3,
}

impl ValueKind {
    const fn decode(value: u8) -> Result<Self, ConfigError> {
        match value {
            1 => Ok(Self::Bool),
            2 => Ok(Self::U64),
            3 => Ok(Self::Bytes),
            _ => Err(ConfigError::InvalidValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigValue {
    kind: ValueKind,
    length: u8,
    bytes: [u8; MAX_CONFIG_VALUE_BYTES],
}

impl ConfigValue {
    pub const fn boolean(value: bool) -> Self {
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        bytes[0] = value as u8;
        Self {
            kind: ValueKind::Bool,
            length: 1,
            bytes,
        }
    }

    pub const fn unsigned(value: u64) -> Self {
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        let encoded = value.to_le_bytes();
        let mut index = 0;
        while index < encoded.len() {
            bytes[index] = encoded[index];
            index += 1;
        }
        Self {
            kind: ValueKind::U64,
            length: 8,
            bytes,
        }
    }

    pub fn bytes(value: &[u8]) -> Result<Self, ConfigError> {
        if value.len() > MAX_CONFIG_VALUE_BYTES {
            return Err(ConfigError::InvalidValue);
        }
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            kind: ValueKind::Bytes,
            length: value.len() as u8,
            bytes,
        })
    }

    pub const fn kind(self) -> ValueKind {
        self.kind
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub const fn as_bool(self) -> Option<bool> {
        if matches!(self.kind, ValueKind::Bool) && self.length == 1 {
            Some(self.bytes[0] != 0)
        } else {
            None
        }
    }

    pub const fn as_u64(self) -> Option<u64> {
        if !matches!(self.kind, ValueKind::U64) || self.length != 8 {
            return None;
        }
        let mut encoded = [0; 8];
        let mut index = 0;
        while index < encoded.len() {
            encoded[index] = self.bytes[index];
            index += 1;
        }
        Some(u64::from_le_bytes(encoded))
    }

    fn decode(
        kind: u8,
        length: u8,
        bytes: &[u8; MAX_CONFIG_VALUE_BYTES],
    ) -> Result<Self, ConfigError> {
        let kind = ValueKind::decode(kind)?;
        let length = usize::from(length);
        if length > MAX_CONFIG_VALUE_BYTES || bytes[length..].iter().any(|byte| *byte != 0) {
            return Err(ConfigError::NonCanonical);
        }
        match kind {
            ValueKind::Bool if length == 1 && bytes[0] <= 1 => {}
            ValueKind::U64 if length == 8 => {}
            ValueKind::Bytes => {}
            _ => return Err(ConfigError::InvalidValue),
        }
        Ok(Self {
            kind,
            length: length as u8,
            bytes: *bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Constraint {
    Bool,
    U64 { minimum: u64, maximum: u64 },
    Bytes { maximum_length: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingSchema {
    setting: SettingId,
    object: ObjectId,
    constraint: Constraint,
}

impl SettingSchema {
    pub const fn boolean(setting: SettingId, object: ObjectId) -> Result<Self, ConfigError> {
        Self::new(setting, object, Constraint::Bool)
    }

    pub const fn unsigned(
        setting: SettingId,
        object: ObjectId,
        minimum: u64,
        maximum: u64,
    ) -> Result<Self, ConfigError> {
        if minimum > maximum {
            return Err(ConfigError::InvalidSchema);
        }
        Self::new(setting, object, Constraint::U64 { minimum, maximum })
    }

    pub const fn bytes(
        setting: SettingId,
        object: ObjectId,
        maximum_length: u8,
    ) -> Result<Self, ConfigError> {
        if maximum_length == 0 || maximum_length as usize > MAX_CONFIG_VALUE_BYTES {
            return Err(ConfigError::InvalidSchema);
        }
        Self::new(setting, object, Constraint::Bytes { maximum_length })
    }

    const fn new(
        setting: SettingId,
        object: ObjectId,
        constraint: Constraint,
    ) -> Result<Self, ConfigError> {
        if object.0 == 0 {
            return Err(ConfigError::InvalidSchema);
        }
        Ok(Self {
            setting,
            object,
            constraint,
        })
    }

    pub const fn setting(self) -> SettingId {
        self.setting
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    fn validate(self, value: ConfigValue) -> Result<(), ConfigError> {
        match (self.constraint, value.kind) {
            (Constraint::Bool, ValueKind::Bool) => Ok(()),
            (Constraint::U64 { minimum, maximum }, ValueKind::U64) => value
                .as_u64()
                .filter(|value| (minimum..=maximum).contains(value))
                .map(|_| ())
                .ok_or(ConfigError::SchemaViolation),
            (Constraint::Bytes { maximum_length }, ValueKind::Bytes)
                if value.length <= maximum_length =>
            {
                Ok(())
            }
            _ => Err(ConfigError::SchemaViolation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidRoot,
    InvalidSetting,
    InvalidSchema,
    DuplicateSetting,
    DuplicateObject,
    Capacity,
    MissingSetting,
    InvalidValue,
    SchemaViolation,
    EmptyTransaction,
    RevisionConflict { current: u64 },
    RevisionExhausted,
    SequenceExhausted,
    Unauthorized(CapabilityError),
    WrongObject,
    AuditUnavailable { oldest: u64 },
    InvalidProtocol,
    UnsupportedVersion,
    Truncated,
    NonCanonical,
    InvalidAuthorityEnvelope,
}

#[derive(Clone, Copy)]
struct SettingEntry {
    schema: SettingSchema,
    value: Option<ConfigValue>,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigRecord {
    pub setting: SettingId,
    pub revision: u64,
    pub value: Option<ConfigValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigUpdate {
    setting: SettingId,
    capability: Capability,
    value: ConfigValue,
}

impl ConfigUpdate {
    pub const fn new(setting: SettingId, capability: Capability, value: ConfigValue) -> Self {
        Self {
            setting,
            capability,
            value,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigTransaction<const UPDATES: usize> {
    expected_revision: u64,
    updates: [Option<ConfigUpdate>; UPDATES],
    count: usize,
}

impl<const UPDATES: usize> ConfigTransaction<UPDATES> {
    pub fn new(expected_revision: u64) -> Self {
        Self {
            expected_revision,
            updates: [None; UPDATES],
            count: 0,
        }
    }

    pub fn push(&mut self, update: ConfigUpdate) -> Result<(), ConfigError> {
        if self.count == UPDATES {
            return Err(ConfigError::Capacity);
        }
        self.updates[self.count] = Some(update);
        self.count += 1;
        Ok(())
    }

    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub revision: u64,
    pub setting: SettingId,
}

pub struct ConfigurationService<const SETTINGS: usize, const AUDIT: usize> {
    root: ObjectId,
    settings: [Option<SettingEntry>; SETTINGS],
    setting_count: usize,
    revision: u64,
    audit: [Option<AuditEvent>; AUDIT],
    audit_head: usize,
    audit_count: usize,
    next_audit_sequence: u64,
}

impl<const SETTINGS: usize, const AUDIT: usize> ConfigurationService<SETTINGS, AUDIT> {
    pub fn new(root: ObjectId, schemas: &[SettingSchema]) -> Result<Self, ConfigError> {
        if root.0 == 0 {
            return Err(ConfigError::InvalidRoot);
        }
        if SETTINGS == 0 || AUDIT == 0 || schemas.is_empty() || schemas.len() > SETTINGS {
            return Err(ConfigError::Capacity);
        }
        for (index, schema) in schemas.iter().enumerate() {
            if schema.object == root {
                return Err(ConfigError::DuplicateObject);
            }
            if schemas[index + 1..]
                .iter()
                .any(|other| other.setting == schema.setting)
            {
                return Err(ConfigError::DuplicateSetting);
            }
            if schemas[index + 1..]
                .iter()
                .any(|other| other.object == schema.object)
            {
                return Err(ConfigError::DuplicateObject);
            }
        }
        let mut settings = array::from_fn(|_| None);
        for (slot, schema) in settings.iter_mut().zip(schemas.iter().copied()) {
            *slot = Some(SettingEntry {
                schema,
                value: None,
                revision: 0,
            });
        }
        Ok(Self {
            root,
            settings,
            setting_count: schemas.len(),
            revision: 0,
            audit: [None; AUDIT],
            audit_head: 0,
            audit_count: 0,
            next_audit_sequence: 1,
        })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn read<const CAPS: usize>(
        &self,
        capabilities: &CapabilitySpace<CAPS>,
        capability: Capability,
        setting: SettingId,
    ) -> Result<ConfigRecord, ConfigError> {
        let entry = self.entry(setting)?;
        Self::authorize(capabilities, capability, Rights::READ, entry.schema.object)?;
        Ok(ConfigRecord {
            setting,
            revision: entry.revision,
            value: entry.value,
        })
    }

    pub fn commit<const CAPS: usize, const UPDATES: usize>(
        &mut self,
        capabilities: &CapabilitySpace<CAPS>,
        root_capability: Capability,
        transaction: &ConfigTransaction<UPDATES>,
    ) -> Result<u64, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::CONTROL, self.root)?;
        if transaction.is_empty() {
            return Err(ConfigError::EmptyTransaction);
        }
        if transaction.expected_revision != self.revision {
            return Err(ConfigError::RevisionConflict {
                current: self.revision,
            });
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionExhausted)?;
        self.next_audit_sequence
            .checked_add(transaction.count as u64)
            .ok_or(ConfigError::SequenceExhausted)?;

        for index in 0..transaction.count {
            let update = transaction.updates[index].ok_or(ConfigError::NonCanonical)?;
            if transaction.updates[..index]
                .iter()
                .flatten()
                .any(|prior| prior.setting == update.setting)
            {
                return Err(ConfigError::DuplicateSetting);
            }
            let entry = self.entry(update.setting)?;
            Self::authorize(
                capabilities,
                update.capability,
                Rights::WRITE,
                entry.schema.object,
            )?;
            entry.schema.validate(update.value)?;
        }

        for update in transaction.updates[..transaction.count]
            .iter()
            .flatten()
            .copied()
        {
            let entry = self.entry_mut(update.setting)?;
            entry.value = Some(update.value);
            entry.revision = next_revision;
            self.push_audit(AuditEvent {
                sequence: self.next_audit_sequence,
                revision: next_revision,
                setting: update.setting,
            });
            self.next_audit_sequence += 1;
        }
        self.revision = next_revision;
        Ok(next_revision)
    }

    pub fn audit_event<const CAPS: usize>(
        &self,
        capabilities: &CapabilitySpace<CAPS>,
        root_capability: Capability,
        sequence: u64,
    ) -> Result<Option<AuditEvent>, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::READ, self.root)?;
        if sequence == 0 || sequence >= self.next_audit_sequence {
            return Ok(None);
        }
        let oldest = self.next_audit_sequence - self.audit_count as u64;
        if sequence < oldest {
            return Err(ConfigError::AuditUnavailable { oldest });
        }
        let offset = usize::try_from(sequence - oldest).map_err(|_| ConfigError::NonCanonical)?;
        Ok(self.audit[(self.audit_head + offset) % AUDIT])
    }

    fn authorize<const CAPS: usize>(
        capabilities: &CapabilitySpace<CAPS>,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        let object = capabilities
            .authorize(capability, rights)
            .map_err(ConfigError::Unauthorized)?;
        if object != expected {
            return Err(ConfigError::WrongObject);
        }
        Ok(())
    }

    fn entry(&self, setting: SettingId) -> Result<&SettingEntry, ConfigError> {
        self.settings[..self.setting_count]
            .iter()
            .flatten()
            .find(|entry| entry.schema.setting == setting)
            .ok_or(ConfigError::MissingSetting)
    }

    fn entry_mut(&mut self, setting: SettingId) -> Result<&mut SettingEntry, ConfigError> {
        self.settings[..self.setting_count]
            .iter_mut()
            .flatten()
            .find(|entry| entry.schema.setting == setting)
            .ok_or(ConfigError::MissingSetting)
    }

    fn push_audit(&mut self, event: AuditEvent) {
        if self.audit_count < AUDIT {
            let tail = (self.audit_head + self.audit_count) % AUDIT;
            self.audit[tail] = Some(event);
            self.audit_count += 1;
        } else {
            self.audit[self.audit_head] = Some(event);
            self.audit_head = (self.audit_head + 1) % AUDIT;
        }
    }
}

// The complete bounded transaction remains inline because this service crate
// has no allocator and decoded authority-bearing requests must own their bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub enum ConfigurationRequest {
    Read {
        request_id: u64,
        setting: SettingId,
        capability: Capability,
    },
    Commit {
        request_id: u64,
        root: Capability,
        transaction: ConfigTransaction<MAX_WIRE_UPDATES>,
    },
}

impl ConfigurationRequest {
    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() < CONFIG_REQUEST_HEADER_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != CONFIG_REQUEST_MAGIC {
            return Err(ConfigError::InvalidProtocol);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let operation = read_u16(input, 6)?;
        let encoded_length = usize::from(read_u16(input, 8)?);
        let count = usize::from(input[10]);
        if encoded_length != input.len()
            || input[11..16].iter().any(|byte| *byte != 0)
            || input[44..48].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        let request_id = read_u64(input, 16)?;
        let expected_revision = read_u64(input, 24)?;
        let authority = Capability::from_token(read_u64(input, 32)?);
        let target = read_u32(input, 40)?;
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        match operation {
            1 if count == 0
                && encoded_length == CONFIG_REQUEST_HEADER_BYTES
                && expected_revision == 0 =>
            {
                Ok(Self::Read {
                    request_id,
                    setting: SettingId::new(target)?,
                    capability: authority,
                })
            }
            2 if (1..=MAX_WIRE_UPDATES).contains(&count) && target == 0 => {
                let wanted = CONFIG_REQUEST_HEADER_BYTES
                    .checked_add(count * CONFIG_UPDATE_BYTES)
                    .ok_or(ConfigError::NonCanonical)?;
                if encoded_length != wanted {
                    return Err(ConfigError::NonCanonical);
                }
                let mut transaction = ConfigTransaction::new(expected_revision);
                for index in 0..count {
                    let start = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES;
                    let setting = SettingId::new(read_u32(input, start)?)?;
                    let kind = input[start + 4];
                    let length = input[start + 5];
                    if input[start + 6..start + 8].iter().any(|byte| *byte != 0) {
                        return Err(ConfigError::NonCanonical);
                    }
                    let capability = Capability::from_token(read_u64(input, start + 8)?);
                    let mut value = [0; MAX_CONFIG_VALUE_BYTES];
                    value.copy_from_slice(&input[start + 16..start + 80]);
                    transaction.push(ConfigUpdate::new(
                        setting,
                        capability,
                        ConfigValue::decode(kind, length, &value)?,
                    ))?;
                }
                Ok(Self::Commit {
                    request_id,
                    root: authority,
                    transaction,
                })
            }
            _ => Err(ConfigError::NonCanonical),
        }
    }

    /// Resolves authority exclusively from capabilities derived by kernel IPC.
    /// Capability-token fields in the payload must be zero placeholders: a
    /// sender cannot predict the receiver-space generations created during
    /// transfer, and payload bytes never carry authority.
    pub fn decode_message(message: &Message) -> Result<Self, ConfigError> {
        let payload = message.payload();
        let mut request = Self::decode(payload)?;
        match &mut request {
            Self::Read { capability, .. } => {
                if payload[32..40].iter().any(|byte| *byte != 0) || message.capability_count() != 1
                {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                *capability = message
                    .capabilities()
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
            }
            Self::Commit {
                root, transaction, ..
            } => {
                if payload[32..40].iter().any(|byte| *byte != 0)
                    || message.capability_count() != transaction.count + 1
                {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                let mut authorities = message.capabilities();
                *root = authorities
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
                for (index, update) in transaction.updates[..transaction.count]
                    .iter_mut()
                    .flatten()
                    .enumerate()
                {
                    let authority_offset =
                        CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES + 8;
                    if payload[authority_offset..authority_offset + 8]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(ConfigError::InvalidAuthorityEnvelope);
                    }
                    update.capability = authorities
                        .next()
                        .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
                }
                if authorities.next().is_some() {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
            }
        }
        Ok(request)
    }
}

pub fn encode_read_message_request(
    request_id: u64,
    setting: SettingId,
    output: &mut [u8; CONFIG_REQUEST_HEADER_BYTES],
) -> Result<(), ConfigError> {
    encode_read_request(request_id, setting, Capability::from_token(0), output)
}

pub fn encode_commit_message_request<const UPDATES: usize>(
    request_id: u64,
    transaction: &ConfigTransaction<UPDATES>,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    let length = encode_commit_request(request_id, Capability::from_token(0), transaction, output)?;
    for index in 0..transaction.count {
        let authority_offset = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES + 8;
        output[authority_offset..authority_offset + 8].fill(0);
    }
    Ok(length)
}

pub fn encode_read_request(
    request_id: u64,
    setting: SettingId,
    capability: Capability,
    output: &mut [u8; CONFIG_REQUEST_HEADER_BYTES],
) -> Result<(), ConfigError> {
    if request_id == 0 {
        return Err(ConfigError::NonCanonical);
    }
    *output = [0; CONFIG_REQUEST_HEADER_BYTES];
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 1)?;
    write_u16(output, 8, CONFIG_REQUEST_HEADER_BYTES as u16)?;
    write_u64(output, 16, request_id)?;
    write_u64(output, 32, capability.token())?;
    write_u32(output, 40, setting.get())
}

pub fn encode_commit_request<const UPDATES: usize>(
    request_id: u64,
    root: Capability,
    transaction: &ConfigTransaction<UPDATES>,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    if request_id == 0 || transaction.is_empty() || transaction.len() > MAX_WIRE_UPDATES {
        return Err(ConfigError::NonCanonical);
    }
    let length = CONFIG_REQUEST_HEADER_BYTES + transaction.len() * CONFIG_UPDATE_BYTES;
    if output.len() < length {
        return Err(ConfigError::Truncated);
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 2)?;
    write_u16(output, 8, length as u16)?;
    output[10] = transaction.len() as u8;
    write_u64(output, 16, request_id)?;
    write_u64(output, 24, transaction.expected_revision())?;
    write_u64(output, 32, root.token())?;
    for (index, update) in transaction.updates[..transaction.count]
        .iter()
        .flatten()
        .copied()
        .enumerate()
    {
        let start = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES;
        write_u32(output, start, update.setting.get())?;
        output[start + 4] = update.value.kind as u8;
        output[start + 5] = update.value.length;
        write_u64(output, start + 8, update.capability.token())?;
        output[start + 16..start + 80].copy_from_slice(&update.value.bytes);
    }
    Ok(length)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ResponseStatus {
    Ok = 0,
    Rejected = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationResponse {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub revision: u64,
    pub setting: Option<SettingId>,
    pub value: Option<ConfigValue>,
}

impl ConfigurationResponse {
    pub fn encode(self, output: &mut [u8; CONFIG_RESPONSE_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0
            || (self.value.is_some() && self.setting.is_none())
            || (self.status == ResponseStatus::Rejected
                && (self.setting.is_some() || self.value.is_some()))
        {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; CONFIG_RESPONSE_BYTES];
        output[..4].copy_from_slice(&CONFIG_RESPONSE_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.status as u16)?;
        write_u16(output, 8, CONFIG_RESPONSE_BYTES as u16)?;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.revision)?;
        if let Some(setting) = self.setting {
            write_u32(output, 32, setting.get())?;
            if let Some(value) = self.value {
                output[36] = value.kind as u8;
                output[37] = value.length;
                output[40..104].copy_from_slice(&value.bytes);
            }
        }
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != CONFIG_RESPONSE_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != CONFIG_RESPONSE_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[10..16].iter().any(|byte| *byte != 0)
            || input[38..40].iter().any(|byte| *byte != 0)
            || input[104..112].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let status = match read_u16(input, 6)? {
            0 => ResponseStatus::Ok,
            1 => ResponseStatus::Rejected,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        let revision = read_u64(input, 24)?;
        let setting = read_u32(input, 32)?;
        let kind = input[36];
        let length = input[37];
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        let (setting, value) = if setting == 0 {
            if kind != 0 || length != 0 || input[40..104].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::NonCanonical);
            }
            (None, None)
        } else {
            if status == ResponseStatus::Rejected {
                return Err(ConfigError::NonCanonical);
            }
            let value = if kind == 0 {
                if length != 0 || input[40..104].iter().any(|byte| *byte != 0) {
                    return Err(ConfigError::NonCanonical);
                }
                None
            } else {
                let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
                bytes.copy_from_slice(&input[40..104]);
                Some(ConfigValue::decode(kind, length, &bytes)?)
            };
            (Some(SettingId::new(setting)?), value)
        };
        Ok(Self {
            request_id,
            status,
            revision,
            setting,
            value,
        })
    }
}

/// Dispatches one kernel-delivered configuration request. Malformed authority
/// envelopes fail without a response; well-formed requests receive either an
/// `Ok` result or a deliberately detail-free rejection so authorization errors
/// do not become an object-discovery oracle.
pub fn dispatch_configuration_message<
    const SETTINGS: usize,
    const AUDIT: usize,
    const CAPS: usize,
>(
    service: &mut ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &CapabilitySpace<CAPS>,
    message: &Message,
    output: &mut [u8; CONFIG_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let request = ConfigurationRequest::decode_message(message)?;
    let response = match request {
        ConfigurationRequest::Read {
            request_id,
            setting,
            capability,
        } => match service.read(capabilities, capability, setting) {
            Ok(record) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision: record.revision,
                setting: Some(record.setting),
                value: record.value,
            },
            Err(_) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Rejected,
                revision: service.revision(),
                setting: None,
                value: None,
            },
        },
        ConfigurationRequest::Commit {
            request_id,
            root,
            transaction,
        } => match service.commit(capabilities, root, &transaction) {
            Ok(revision) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision,
                setting: None,
                value: None,
            },
            Err(_) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Rejected,
                revision: service.revision(),
                setting: None,
                value: None,
            },
        },
    };
    response.encode(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SupervisionOperation {
    Query = 1,
    Restart = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionRequest {
    pub operation: SupervisionOperation,
    pub request_id: u64,
    pub service: ServiceId,
    pub capability: Capability,
    pub now: u64,
}

impl SupervisionRequest {
    pub fn encode(self, output: &mut [u8; SUPERVISION_REQUEST_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0 || (self.operation == SupervisionOperation::Query && self.now != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; SUPERVISION_REQUEST_BYTES];
        output[..4].copy_from_slice(&SUPERVISION_REQUEST_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.operation as u16)?;
        write_u16(output, 8, SUPERVISION_REQUEST_BYTES as u16)?;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.service.token())?;
        write_u64(output, 32, self.capability.token())?;
        write_u64(output, 40, self.now)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != SUPERVISION_REQUEST_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != SUPERVISION_REQUEST_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[10..16].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let operation = match read_u16(input, 6)? {
            1 => SupervisionOperation::Query,
            2 => SupervisionOperation::Restart,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        let now = read_u64(input, 40)?;
        if request_id == 0 || (operation == SupervisionOperation::Query && now != 0) {
            return Err(ConfigError::NonCanonical);
        }
        Ok(Self {
            operation,
            request_id,
            service: ServiceId::from_token(read_u64(input, 24)?),
            capability: Capability::from_token(read_u64(input, 32)?),
            now,
        })
    }

    pub fn encode_message(
        self,
        output: &mut [u8; SUPERVISION_REQUEST_BYTES],
    ) -> Result<(), ConfigError> {
        let mut request = self;
        request.capability = Capability::from_token(0);
        request.encode(output)
    }

    pub fn decode_message(message: &Message) -> Result<Self, ConfigError> {
        if message.payload().len() != SUPERVISION_REQUEST_BYTES
            || message.payload()[32..40].iter().any(|byte| *byte != 0)
            || message.capability_count() != 1
        {
            return Err(ConfigError::InvalidAuthorityEnvelope);
        }
        let mut request = Self::decode(message.payload())?;
        request.capability = message
            .capabilities()
            .next()
            .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SupervisionState {
    Running = 1,
    Exited = 2,
    Faulted = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionResponse {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub service: ServiceId,
    pub state: SupervisionState,
    pub detail: u64,
}

impl SupervisionResponse {
    pub fn encode(self, output: &mut [u8; SUPERVISION_RESPONSE_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; SUPERVISION_RESPONSE_BYTES];
        output[..4].copy_from_slice(&SUPERVISION_RESPONSE_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.status as u16)?;
        write_u16(output, 8, SUPERVISION_RESPONSE_BYTES as u16)?;
        output[10] = self.state as u8;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.service.token())?;
        write_u64(output, 32, self.detail)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != SUPERVISION_RESPONSE_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != SUPERVISION_RESPONSE_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[11..16].iter().any(|byte| *byte != 0)
            || input[40..48].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let status = match read_u16(input, 6)? {
            0 => ResponseStatus::Ok,
            1 => ResponseStatus::Rejected,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let state = match input[10] {
            1 => SupervisionState::Running,
            2 => SupervisionState::Exited,
            3 => SupervisionState::Faulted,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        Ok(Self {
            request_id,
            status,
            service: ServiceId::from_token(read_u64(input, 24)?),
            state,
            detail: read_u64(input, 32)?,
        })
    }
}

/// Composes a kernel-derived management capability with the existing bounded
/// supervisor. The caller supplies a trusted fresh launch context; no address,
/// priority, or executable choice is accepted from the untrusted request.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_supervision_message<
    const SERVICES: usize,
    const TASKS: usize,
    const TASK_CAPS: usize,
    const MANAGEMENT_CAPS: usize,
>(
    supervisor: &mut ServiceSupervisor<SERVICES>,
    management: &CapabilitySpace<MANAGEMENT_CAPS>,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPS>,
    message: &Message,
    priority: Priority,
    fresh_context: UserContext,
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let request = SupervisionRequest::decode_message(message)?;
    let (status, service, state) = match request.operation {
        SupervisionOperation::Query => {
            match supervisor.state_authorized(request.service, management, request.capability) {
                Ok(state) => (ResponseStatus::Ok, request.service, state.into()),
                Err(_) => (
                    ResponseStatus::Rejected,
                    request.service,
                    SupervisionState::Exited,
                ),
            }
        }
        SupervisionOperation::Restart => match supervisor.restart_at(
            request.service,
            management,
            request.capability,
            runtime,
            priority,
            fresh_context,
            request.now,
        ) {
            Ok(replacement) => (ResponseStatus::Ok, replacement, SupervisionState::Running),
            Err(_) => (
                ResponseStatus::Rejected,
                request.service,
                SupervisionState::Exited,
            ),
        },
    };
    SupervisionResponse {
        request_id: request.request_id,
        status,
        service,
        state,
        detail: 0,
    }
    .encode(output)
}

impl From<ServiceState> for SupervisionState {
    fn from(value: ServiceState) -> Self {
        match value {
            ServiceState::Running => Self::Running,
            ServiceState::Exited => Self::Exited,
            ServiceState::Faulted => Self::Faulted,
        }
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ConfigError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ConfigError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, ConfigError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 2)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        ConfigurationService<3, 2>,
        CapabilitySpace<4>,
        Capability,
        Capability,
        Capability,
    ) {
        let enabled = SettingId::new(1).unwrap();
        let limit = SettingId::new(2).unwrap();
        let schemas = [
            SettingSchema::boolean(enabled, ObjectId(11)).unwrap(),
            SettingSchema::unsigned(limit, ObjectId(12), 1, 100).unwrap(),
        ];
        let service = ConfigurationService::new(ObjectId(10), &schemas).unwrap();
        let mut capabilities = CapabilitySpace::new();
        let root = capabilities
            .insert(ObjectId(10), Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let enabled_capability = capabilities
            .insert(ObjectId(11), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let limit_capability = capabilities
            .insert(ObjectId(12), Rights::READ.union(Rights::WRITE))
            .unwrap();
        (
            service,
            capabilities,
            root,
            enabled_capability,
            limit_capability,
        )
    }

    #[test]
    fn atomic_commit_requires_root_and_each_exact_setting_capability() {
        let (mut service, capabilities, root, enabled, limit) = fixture();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        assert_eq!(service.commit(&capabilities, root, &transaction), Ok(1));
        assert_eq!(
            service
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );
        assert_eq!(
            service
                .read(&capabilities, limit, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
    }

    #[test]
    fn late_schema_or_authority_failure_rolls_back_every_update() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                enabled,
                ConfigValue::unsigned(101),
            ))
            .unwrap();
        assert_eq!(
            service.commit(&capabilities, root, &transaction),
            Err(ConfigError::WrongObject)
        );
        assert_eq!(service.revision(), 0);
        assert_eq!(
            service
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value,
            None
        );
    }

    #[test]
    fn stale_revision_duplicate_setting_and_stale_capability_fail_closed() {
        let (mut service, mut capabilities, root, enabled, _) = fixture();
        let stale = enabled;
        capabilities.revoke(enabled).unwrap();
        let replacement = capabilities
            .insert(ObjectId(11), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let mut stale_transaction = ConfigTransaction::<1>::new(0);
        stale_transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                stale,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        assert!(matches!(
            service.commit(&capabilities, root, &stale_transaction),
            Err(ConfigError::Unauthorized(CapabilityError::Invalid))
        ));
        let mut duplicate = ConfigTransaction::<2>::new(0);
        for value in [true, false] {
            duplicate
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    replacement,
                    ConfigValue::boolean(value),
                ))
                .unwrap();
        }
        assert_eq!(
            service.commit(&capabilities, root, &duplicate),
            Err(ConfigError::DuplicateSetting)
        );
        assert_eq!(service.revision(), 0);
    }

    #[test]
    fn bounded_audit_reports_overwrite_gap_with_monotonic_sequence() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        for revision in 0..3 {
            let mut transaction = ConfigTransaction::<1>::new(revision);
            transaction
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    enabled,
                    ConfigValue::boolean(revision % 2 == 0),
                ))
                .unwrap();
            service.commit(&capabilities, root, &transaction).unwrap();
        }
        assert_eq!(
            service.audit_event(&capabilities, root, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            service.audit_event(&capabilities, root, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 3,
                setting: SettingId::new(1).unwrap(),
            })
        );
    }

    #[test]
    fn configuration_wire_is_canonical_bounded_and_pointer_free() {
        let (_, _, root, enabled, limit) = fixture();
        let mut read_wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_request(8, SettingId::new(1).unwrap(), enabled, &mut read_wire).unwrap();
        assert_eq!(
            ConfigurationRequest::decode(&read_wire),
            Ok(ConfigurationRequest::Read {
                request_id: 8,
                setting: SettingId::new(1).unwrap(),
                capability: enabled,
            })
        );
        let mut transaction = ConfigTransaction::<2>::new(7);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(9),
            ))
            .unwrap();
        let mut wire = [0xa5; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_request(9, root, &transaction, &mut wire).unwrap();
        let decoded = ConfigurationRequest::decode(&wire[..length]).unwrap();
        let ConfigurationRequest::Commit {
            request_id,
            root: decoded_root,
            transaction: decoded_transaction,
        } = decoded
        else {
            panic!("expected commit");
        };
        assert_eq!(request_id, 9);
        assert_eq!(decoded_root, root);
        assert_eq!(decoded_transaction.len(), 2);
        let mut malformed = wire;
        malformed[11] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&malformed[..length]),
            Err(ConfigError::NonCanonical)
        );
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length - 1]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn kernel_message_authorities_replace_payload_tokens_and_dispatch_atomically() {
        let schemas = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap(),
            SettingSchema::unsigned(SettingId::new(2).unwrap(), ObjectId(12), 1, 100).unwrap(),
        ];
        let mut service = ConfigurationService::<2, 2>::new(ObjectId(10), &schemas).unwrap();
        let context = |root, entry| {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        };
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(99);
        let sender_space = runtime.capabilities_mut(sender).unwrap();
        let endpoint_capability = sender_space
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = sender_space
            .insert(ObjectId(10), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let enabled = sender_space
            .insert(ObjectId(11), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let limit = sender_space
            .insert(ObjectId(12), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(17),
            ))
            .unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_message_request(21, &transaction, &mut wire).unwrap();
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        assert!(wire[56..64].iter().all(|byte| *byte == 0));
        assert!(wire[136..144].iter().all(|byte| *byte == 0));
        let mut endpoint = mrml_kernel::Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                &wire[..length],
                &[
                    (root, Rights::CONTROL),
                    (enabled, Rights::WRITE),
                    (limit, Rights::WRITE),
                ],
            )
            .unwrap();
        let mut delivered_authorities = message.capabilities();
        let delivered = [
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
        ];
        assert!(delivered_authorities.next().is_none());
        assert_ne!(delivered[0], root);
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(
            &mut service,
            runtime.capabilities_mut(receiver).unwrap(),
            &message,
            &mut response_wire,
        )
        .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire)
                .unwrap()
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(service.revision(), 1);

        let extra = Message::new(
            &wire[..length],
            &[delivered[0], delivered[1], delivered[2], delivered[0]],
        )
        .unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&extra),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32] = 1;
        let forged = Message::new(&forged[..length], &delivered).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn message_dispatch_represents_an_authorized_unset_value() {
        let (mut service, capabilities, _, enabled, _) = fixture();
        let mut wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_message_request(22, SettingId::new(1).unwrap(), &mut wire).unwrap();
        let message = Message::new(&wire, &[enabled]).unwrap();
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response_wire)
            .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire),
            Ok(ConfigurationResponse {
                request_id: 22,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(SettingId::new(1).unwrap()),
                value: None,
            })
        );
    }

    #[test]
    fn supervision_wire_binds_generation_authority_time_and_version() {
        let (_, _, root, _, _) = fixture();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 4,
            service: ServiceId::from_token((3u64 << 32) | 2),
            capability: root,
            now: 99,
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        assert_eq!(SupervisionRequest::decode(&wire), Ok(request));
        wire[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::UnsupportedVersion)
        );
        wire[4..6].copy_from_slice(&SYSTEM_PROTOCOL_VERSION.to_le_bytes());
        wire[12] = 1;
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let response = SupervisionResponse {
            request_id: 4,
            status: ResponseStatus::Ok,
            service: request.service,
            state: SupervisionState::Faulted,
            detail: 123,
        };
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        response.encode(&mut response_wire).unwrap();
        assert_eq!(SupervisionResponse::decode(&response_wire), Ok(response));
        response_wire[47] = 1;
        assert_eq!(
            SupervisionResponse::decode(&response_wire),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn supervision_message_uses_derived_control_and_trusted_restart_context() {
        struct Eraser;
        impl mrml_kernel::ServiceAddressSpaceEraser for Eraser {
            type Error = ();

            fn erase(&mut self, _: mrml_kernel::TaskId, _: UserContext) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        fn context(root: u64, entry: u64) -> UserContext {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        }

        let object = ObjectId(70);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let retired_service = supervisor.register(object, task).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 31,
            service: retired_service,
            capability: control,
            now: 0,
        };
        let mut request_wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode_message(&mut request_wire).unwrap();
        assert!(request_wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&request_wire, &[control]).unwrap();
        let fresh = context(0x30_0000, 0x50_0000);
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_message(
            &mut supervisor,
            &management,
            &mut runtime,
            &message,
            Priority::RESPONSIVE,
            fresh,
            &mut response_wire,
        )
        .unwrap();
        let response = SupervisionResponse::decode(&response_wire).unwrap();
        assert_eq!(response.status, ResponseStatus::Ok);
        assert_eq!(response.state, SupervisionState::Running);
        assert_ne!(response.service, retired_service);
        assert_eq!(
            supervisor.state(response.service),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            runtime.context(supervisor.task(response.service).unwrap().unwrap()),
            Ok(&fresh)
        );

        let forged = Message::new(&request_wire, &[]).unwrap();
        assert_eq!(
            SupervisionRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn configuration_responses_round_trip_and_reject_hidden_tail_data() {
        let response = ConfigurationResponse {
            request_id: 7,
            status: ResponseStatus::Ok,
            revision: 3,
            setting: Some(SettingId::new(2).unwrap()),
            value: Some(ConfigValue::unsigned(44)),
        };
        let mut wire = [0; CONFIG_RESPONSE_BYTES];
        response.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(response));
        wire[111] = 1;
        assert_eq!(
            ConfigurationResponse::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let rejected = ConfigurationResponse {
            request_id: 8,
            status: ResponseStatus::Rejected,
            revision: 3,
            setting: None,
            value: None,
        };
        rejected.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(rejected));
    }

    #[test]
    fn schema_and_identifiers_reject_ambiguous_inputs() {
        assert_eq!(SettingId::new(0), Err(ConfigError::InvalidSetting));
        assert!(SettingSchema::unsigned(SettingId::new(1).unwrap(), ObjectId(1), 2, 1).is_err());
        let duplicate = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(1)).unwrap(),
            SettingSchema::bytes(SettingId::new(1).unwrap(), ObjectId(2), 8).unwrap(),
        ];
        assert!(matches!(
            ConfigurationService::<2, 1>::new(ObjectId(9), &duplicate),
            Err(ConfigError::DuplicateSetting)
        ));
        let aliases_root =
            [SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(9)).unwrap()];
        assert!(matches!(
            ConfigurationService::<1, 1>::new(ObjectId(9), &aliases_root),
            Err(ConfigError::DuplicateObject)
        ));
    }
}
