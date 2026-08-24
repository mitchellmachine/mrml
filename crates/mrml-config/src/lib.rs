#![no_std]

//! Fixed-capacity policy/configuration service foundation.
//!
//! Setting identifiers select records; they never authorize access. Every
//! read and transaction update repeats exact capability checks against the
//! schema-bound object. Transactions preflight all schema, authority, revision,
//! capacity, and sequence conditions before the first mutation.

use core::array;

use mrml_crypto::Sha3_256;
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, Message, ObjectId, Priority, Rights, ServiceId,
    ServiceState, ServiceSupervisor, TaskRuntime,
};
use mrml_storage::{
    ExtentMap, FileMetadata, FileReadBackend, FileReadError, FileState, FileWriteBackend,
    FileWriteError, MetadataPointer, PreparedFileWrite, StorageAuthorityTable, StorageHandle,
    StoragePrincipal, StorageTransaction, TransactionError, TransactionReceipt,
};

pub const MAX_CONFIG_VALUE_BYTES: usize = 64;
pub const MAX_WIRE_UPDATES: usize = 4;
pub const CONFIG_REQUEST_HEADER_BYTES: usize = 48;
pub const CONFIG_UPDATE_BYTES: usize = 80;
pub const CONFIG_SCHEMA_BYTES: usize = 32;
pub const MAX_CONFIG_REQUEST_BYTES: usize =
    CONFIG_REQUEST_HEADER_BYTES + MAX_WIRE_UPDATES * CONFIG_UPDATE_BYTES;
pub const CONFIG_RESPONSE_BYTES: usize = 112;
pub const SUPERVISION_REQUEST_BYTES: usize = 48;
pub const SUPERVISION_RESPONSE_BYTES: usize = 48;
pub const SYSTEM_PROTOCOL_VERSION: u16 = 1;
pub const CONFIG_CHECKPOINT_HEADER_BYTES: usize = 96;
pub const CONFIG_CHECKPOINT_SETTING_BYTES: usize = 112;
pub const CONFIG_CHECKPOINT_AUDIT_BYTES: usize = 24;

const CONFIG_REQUEST_MAGIC: [u8; 4] = *b"MRCQ";
const CONFIG_RESPONSE_MAGIC: [u8; 4] = *b"MRCP";
const SUPERVISION_REQUEST_MAGIC: [u8; 4] = *b"MRSQ";
const SUPERVISION_RESPONSE_MAGIC: [u8; 4] = *b"MRSP";
const CONFIG_CHECKPOINT_MAGIC: [u8; 4] = *b"MRCK";
const CONFIG_CHECKPOINT_DIGEST_OFFSET: usize = 64;
const CONFIG_CHECKPOINT_DIGEST_BYTES: usize = 32;

/// The service asks the kernel to validate opaque handles; it never owns or
/// enumerates the kernel capability space. Rejection deliberately carries no
/// object or rights detail.
pub trait CapabilityAuthorizer {
    fn authorize_exact(
        &self,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError>;
}

/// The supervision service asks the kernel to combine an opaque service token
/// with an independently delivered capability. Rejection deliberately exposes
/// no object, generation, rights, or lifecycle detail.
pub trait ServiceStateAuthorizer {
    fn query_state(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceState, ConfigError>;
}

pub trait ServiceRestartAuthorizer {
    fn restart_service(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceId, ConfigError>;
}

impl<const CAPS: usize> CapabilityAuthorizer for CapabilitySpace<CAPS> {
    fn authorize_exact(
        &self,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        let object = self
            .authorize(capability, rights)
            .map_err(ConfigError::Unauthorized)?;
        (object == expected)
            .then_some(())
            .ok_or(ConfigError::WrongObject)
    }
}

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
    SchemaFrozen,
    Unauthorized(CapabilityError),
    WrongObject,
    AuditUnavailable { oldest: u64 },
    InvalidProtocol,
    UnsupportedVersion,
    Truncated,
    NonCanonical,
    InvalidAuthorityEnvelope,
    InvalidCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationCheckpoint {
    pub length: usize,
    pub digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
}

/// A checkpoint staged into a fresh stable-file generation. The successor
/// remains inactive until an exact storage transaction receipt is consumed.
pub struct PreparedStableConfiguration<const EXTENTS: usize> {
    file: PreparedFileWrite<EXTENTS>,
    checkpoint: ConfigurationCheckpoint,
    revision: u64,
}

impl<const EXTENTS: usize> PreparedStableConfiguration<EXTENTS> {
    pub const fn checkpoint(&self) -> ConfigurationCheckpoint {
        self.checkpoint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn admit<const PARTICIPANTS: usize, const WRITES: usize>(
        &self,
        transaction: &mut StorageTransaction<PARTICIPANTS, WRITES>,
    ) -> Result<(), TransactionError> {
        transaction.admit_file(&self.file)
    }

    pub fn commit<const PARTICIPANTS: usize>(
        self,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableConfiguration<EXTENTS>, TransactionError> {
        let file = self.file.commit_transaction(receipt)?;
        Ok(StableConfiguration {
            file,
            checkpoint: self.checkpoint,
            revision: self.revision,
        })
    }
}

/// Exact stable object generation containing one authenticated checkpoint.
pub struct StableConfiguration<const EXTENTS: usize> {
    file: FileState<EXTENTS>,
    checkpoint: ConfigurationCheckpoint,
    revision: u64,
}

impl<const EXTENTS: usize> StableConfiguration<EXTENTS> {
    pub const fn file(&self) -> &FileState<EXTENTS> {
        &self.file
    }

    pub const fn checkpoint(&self) -> ConfigurationCheckpoint {
        self.checkpoint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationStorageError<E> {
    Configuration(ConfigError),
    InvalidBinding,
    Read(FileReadError<E>),
    Write(FileWriteError<E>),
}

/// Exports and stages a checkpoint as the complete content of the next
/// capability-authorized stable file generation. Publication and activation
/// remain separate and require `StorageTransaction` plus its one-use receipt.
#[allow(clippy::too_many_arguments)]
pub fn prepare_stable_configuration<
    const SETTINGS: usize,
    const AUDIT: usize,
    const CURRENT_EXTENTS: usize,
    const NEXT_EXTENTS: usize,
    const AUTHORITIES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileWriteBackend,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    root_capability: Capability,
    current_file: &FileState<CURRENT_EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    next_extents: ExtentMap<NEXT_EXTENTS>,
    next_metadata: FileMetadata,
    file_metadata_pointer: MetadataPointer,
    protected_metadata: &[MetadataPointer],
    output: &mut [u8],
    backend: &mut B,
) -> Result<PreparedStableConfiguration<NEXT_EXTENTS>, ConfigurationStorageError<B::Error>> {
    let checkpoint = configuration
        .export_checkpoint(capabilities, root_capability, output)
        .map_err(ConfigurationStorageError::Configuration)?;
    let bytes = &output[..checkpoint.length];
    let checkpoint_length =
        u64::try_from(checkpoint.length).map_err(|_| ConfigurationStorageError::InvalidBinding)?;
    let mut content = Sha3_256::new();
    content.update(bytes);
    if next_metadata.object() != current_file.object()
        || next_metadata.generation() != current_file.generation().checked_add(1).unwrap_or(0)
        || next_metadata.length() != checkpoint_length
        || next_metadata.content_digest() != content.finalize()
    {
        return Err(ConfigurationStorageError::InvalidBinding);
    }
    let prepared = current_file
        .prepare_write(
            storage_authority,
            file,
            principal,
            0,
            bytes,
            checkpoint_length,
            next_extents,
            next_metadata,
            file_metadata_pointer,
            protected_metadata,
            backend,
        )
        .map_err(ConfigurationStorageError::Write)?;
    Ok(PreparedStableConfiguration {
        file: prepared,
        checkpoint,
        revision: configuration.revision(),
    })
}

/// Recovers only from one exact file generation already selected by
/// authenticated reachable-storage recovery. It never searches older
/// generations or turns an I/O failure into rollback.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_configuration<
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    const AUTHORITIES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
>(
    file_state: &FileState<EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    capabilities: &A,
    root_capability: Capability,
    input: &mut [u8],
    backend: &mut B,
) -> Result<ConfigurationService<SETTINGS, AUDIT>, ConfigurationStorageError<B::Error>> {
    input.fill(0);
    if expected_file_generation == 0 || file_state.generation() != expected_file_generation {
        return Err(ConfigurationStorageError::InvalidBinding);
    }
    let setting_bytes = SETTINGS
        .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let audit_bytes = AUDIT
        .checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let maximum = CONFIG_CHECKPOINT_HEADER_BYTES
        .checked_add(setting_bytes)
        .and_then(|length| length.checked_add(audit_bytes))
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let length = usize::try_from(file_state.length())
        .ok()
        .filter(|length| {
            *length >= CONFIG_CHECKPOINT_HEADER_BYTES
                && *length <= input.len()
                && *length <= maximum
        })
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    file_state
        .read(
            storage_authority,
            file,
            principal,
            0,
            &mut input[..length],
            backend,
        )
        .map_err(ConfigurationStorageError::Read)?;
    let digest = input[CONFIG_CHECKPOINT_DIGEST_OFFSET
        ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
        .try_into()
        .map_err(|_| ConfigurationStorageError::InvalidBinding)?;
    ConfigurationService::recover_checkpoint(
        capabilities,
        root_capability,
        &input[..length],
        digest,
    )
    .map_err(ConfigurationStorageError::Configuration)
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
    pub fn empty(root: ObjectId) -> Result<Self, ConfigError> {
        if root.0 == 0 {
            return Err(ConfigError::InvalidRoot);
        }
        if SETTINGS == 0 || AUDIT == 0 {
            return Err(ConfigError::Capacity);
        }
        Ok(Self {
            root,
            settings: array::from_fn(|_| None),
            setting_count: 0,
            revision: 0,
            audit: [None; AUDIT],
            audit_head: 0,
            audit_count: 0,
            next_audit_sequence: 1,
        })
    }

    pub fn new(root: ObjectId, schemas: &[SettingSchema]) -> Result<Self, ConfigError> {
        if root.0 == 0 {
            return Err(ConfigError::InvalidRoot);
        }
        if schemas.is_empty() || schemas.len() > SETTINGS {
            return Err(ConfigError::Capacity);
        }
        let mut service = Self::empty(root)?;
        for schema in schemas.iter().copied() {
            service.insert_schema(schema)?;
        }
        Ok(service)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn setting_count(&self) -> usize {
        self.setting_count
    }

    pub fn admit_schema<A: CapabilityAuthorizer + ?Sized>(
        &mut self,
        capabilities: &A,
        root_capability: Capability,
        schema: SettingSchema,
    ) -> Result<(), ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::CONTROL, self.root)?;
        if self.revision != 0 {
            return Err(ConfigError::SchemaFrozen);
        }
        self.insert_schema(schema)
    }

    pub fn export_checkpoint<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        root_capability: Capability,
        output: &mut [u8],
    ) -> Result<ConfigurationCheckpoint, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::READ, self.root)?;
        let length = CONFIG_CHECKPOINT_HEADER_BYTES
            .checked_add(
                self.setting_count
                    .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
                    .ok_or(ConfigError::InvalidCheckpoint)?,
            )
            .and_then(|length| {
                length.checked_add(
                    self.audit_count
                        .checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)?,
                )
            })
            .ok_or(ConfigError::InvalidCheckpoint)?;
        if output.len() < length || length > u32::MAX as usize {
            return Err(ConfigError::Truncated);
        }
        output[..length].fill(0);
        output[..4].copy_from_slice(&CONFIG_CHECKPOINT_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, CONFIG_CHECKPOINT_HEADER_BYTES as u16)?;
        write_u32(output, 8, length as u32)?;
        write_u16(
            output,
            12,
            u16::try_from(self.setting_count).map_err(|_| ConfigError::InvalidCheckpoint)?,
        )?;
        write_u16(
            output,
            14,
            u16::try_from(self.audit_count).map_err(|_| ConfigError::InvalidCheckpoint)?,
        )?;
        write_u64(output, 16, self.root.0)?;
        write_u64(output, 24, self.revision)?;
        write_u64(output, 32, self.next_audit_sequence)?;

        for (index, entry) in self.settings[..self.setting_count]
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            let start = CONFIG_CHECKPOINT_HEADER_BYTES + index * CONFIG_CHECKPOINT_SETTING_BYTES;
            write_u32(output, start, entry.schema.setting.get())?;
            write_u64(output, start + 8, entry.schema.object.0)?;
            write_u64(output, start + 16, entry.revision)?;
            match entry.schema.constraint {
                Constraint::Bool => output[start + 4] = 1,
                Constraint::U64 { minimum, maximum } => {
                    output[start + 4] = 2;
                    write_u64(output, start + 24, minimum)?;
                    write_u64(output, start + 32, maximum)?;
                }
                Constraint::Bytes { maximum_length } => {
                    output[start + 4] = 3;
                    output[start + 5] = maximum_length;
                }
            }
            if let Some(value) = entry.value {
                output[start + 6] = 1;
                output[start + 7] = value.kind as u8;
                output[start + 40] = value.length;
                output[start + 48..start + 112].copy_from_slice(&value.bytes);
            }
        }
        let audit_start =
            CONFIG_CHECKPOINT_HEADER_BYTES + self.setting_count * CONFIG_CHECKPOINT_SETTING_BYTES;
        for index in 0..self.audit_count {
            let event = self.audit[(self.audit_head + index) % AUDIT]
                .ok_or(ConfigError::InvalidCheckpoint)?;
            let start = audit_start + index * CONFIG_CHECKPOINT_AUDIT_BYTES;
            write_u64(output, start, event.sequence)?;
            write_u64(output, start + 8, event.revision)?;
            write_u32(output, start + 16, event.setting.get())?;
        }
        let digest = checkpoint_digest(&output[..length]);
        output[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        Ok(ConfigurationCheckpoint { length, digest })
    }

    pub fn recover_checkpoint<A: CapabilityAuthorizer + ?Sized>(
        capabilities: &A,
        root_capability: Capability,
        input: &[u8],
        expected_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
    ) -> Result<Self, ConfigError> {
        if input.len() < CONFIG_CHECKPOINT_HEADER_BYTES
            || input[..4] != CONFIG_CHECKPOINT_MAGIC
            || read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION
            || usize::from(read_u16(input, 6)?) != CONFIG_CHECKPOINT_HEADER_BYTES
            || usize::try_from(read_u32(input, 8)?).ok() != Some(input.len())
            || input[40..CONFIG_CHECKPOINT_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let embedded_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES] = input
            [CONFIG_CHECKPOINT_DIGEST_OFFSET
                ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .try_into()
            .map_err(|_| ConfigError::InvalidCheckpoint)?;
        if embedded_digest != expected_digest || checkpoint_digest(input) != expected_digest {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let setting_count = usize::from(read_u16(input, 12)?);
        let audit_count = usize::from(read_u16(input, 14)?);
        if setting_count > SETTINGS || audit_count > AUDIT {
            return Err(ConfigError::Capacity);
        }
        let wanted = CONFIG_CHECKPOINT_HEADER_BYTES
            .checked_add(
                setting_count
                    .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
                    .ok_or(ConfigError::InvalidCheckpoint)?,
            )
            .and_then(|length| {
                length.checked_add(audit_count.checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)?)
            })
            .ok_or(ConfigError::InvalidCheckpoint)?;
        if wanted != input.len() {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let root = ObjectId(read_u64(input, 16)?);
        Self::authorize(capabilities, root_capability, Rights::CONTROL, root)?;
        let revision = read_u64(input, 24)?;
        let next_audit_sequence = read_u64(input, 32)?;
        let mut service = Self::empty(root)?;
        for index in 0..setting_count {
            let start = CONFIG_CHECKPOINT_HEADER_BYTES + index * CONFIG_CHECKPOINT_SETTING_BYTES;
            if input[start + 41..start + 48].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::InvalidCheckpoint);
            }
            let setting = SettingId::new(read_u32(input, start)?)?;
            let object = ObjectId(read_u64(input, start + 8)?);
            let minimum = read_u64(input, start + 24)?;
            let maximum = read_u64(input, start + 32)?;
            let schema = match input[start + 4] {
                1 if input[start + 5] == 0 && minimum == 0 && maximum == 0 => {
                    SettingSchema::boolean(setting, object)?
                }
                2 if input[start + 5] == 0 => {
                    SettingSchema::unsigned(setting, object, minimum, maximum)?
                }
                3 if minimum == 0 && maximum == 0 => {
                    SettingSchema::bytes(setting, object, input[start + 5])?
                }
                _ => return Err(ConfigError::InvalidCheckpoint),
            };
            service.insert_schema(schema)?;
            let entry_revision = read_u64(input, start + 16)?;
            let value = match input[start + 6] {
                0 if input[start + 7] == 0
                    && input[start + 40] == 0
                    && input[start + 48..start + 112].iter().all(|byte| *byte == 0)
                    && entry_revision == 0 =>
                {
                    None
                }
                1 if entry_revision != 0 && entry_revision <= revision => {
                    let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
                    bytes.copy_from_slice(&input[start + 48..start + 112]);
                    let value = ConfigValue::decode(input[start + 7], input[start + 40], &bytes)?;
                    schema.validate(value)?;
                    Some(value)
                }
                _ => return Err(ConfigError::InvalidCheckpoint),
            };
            let entry = service.entry_mut(setting)?;
            entry.value = value;
            entry.revision = entry_revision;
        }
        if next_audit_sequence == 0
            || next_audit_sequence <= audit_count as u64
            || (revision == 0 && (audit_count != 0 || next_audit_sequence != 1))
            || (revision != 0 && audit_count == 0)
        {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let first_sequence = next_audit_sequence - audit_count as u64;
        let audit_start =
            CONFIG_CHECKPOINT_HEADER_BYTES + setting_count * CONFIG_CHECKPOINT_SETTING_BYTES;
        let mut prior_audit_revision = 0;
        for index in 0..audit_count {
            let start = audit_start + index * CONFIG_CHECKPOINT_AUDIT_BYTES;
            if input[start + 20..start + 24].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::InvalidCheckpoint);
            }
            let event = AuditEvent {
                sequence: read_u64(input, start)?,
                revision: read_u64(input, start + 8)?,
                setting: SettingId::new(read_u32(input, start + 16)?)?,
            };
            if event.sequence != first_sequence + index as u64
                || event.revision == 0
                || event.revision > revision
                || event.revision < prior_audit_revision
                || service
                    .entry(event.setting)
                    .map(|entry| entry.revision < event.revision)
                    .unwrap_or(true)
            {
                return Err(ConfigError::InvalidCheckpoint);
            }
            prior_audit_revision = event.revision;
            service.audit[index] = Some(event);
        }
        service.revision = revision;
        service.audit_head = 0;
        service.audit_count = audit_count;
        service.next_audit_sequence = next_audit_sequence;
        Ok(service)
    }

    pub fn read<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
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

    pub fn commit<A: CapabilityAuthorizer + ?Sized, const UPDATES: usize>(
        &mut self,
        capabilities: &A,
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

    pub fn audit_event<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
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

    fn authorize<A: CapabilityAuthorizer + ?Sized>(
        capabilities: &A,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        capabilities.authorize_exact(capability, rights, expected)
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

    fn insert_schema(&mut self, schema: SettingSchema) -> Result<(), ConfigError> {
        if schema.object == self.root
            || self.settings[..self.setting_count]
                .iter()
                .flatten()
                .any(|entry| entry.schema.object == schema.object)
        {
            return Err(ConfigError::DuplicateObject);
        }
        if self.settings[..self.setting_count]
            .iter()
            .flatten()
            .any(|entry| entry.schema.setting == schema.setting)
        {
            return Err(ConfigError::DuplicateSetting);
        }
        let slot = self
            .settings
            .get_mut(self.setting_count)
            .ok_or(ConfigError::Capacity)?;
        *slot = Some(SettingEntry {
            schema,
            value: None,
            revision: 0,
        });
        self.setting_count += 1;
        Ok(())
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
    AdmitSchema {
        request_id: u64,
        root: Capability,
        schema: SettingSchema,
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
            3 if count == 0
                && expected_revision == 0
                && encoded_length == CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES =>
            {
                let object = ObjectId(read_u64(input, CONFIG_REQUEST_HEADER_BYTES)?);
                let kind = input[CONFIG_REQUEST_HEADER_BYTES + 8];
                let maximum_length = input[CONFIG_REQUEST_HEADER_BYTES + 9];
                if input[CONFIG_REQUEST_HEADER_BYTES + 10..CONFIG_REQUEST_HEADER_BYTES + 16]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(ConfigError::NonCanonical);
                }
                let minimum = read_u64(input, CONFIG_REQUEST_HEADER_BYTES + 16)?;
                let maximum = read_u64(input, CONFIG_REQUEST_HEADER_BYTES + 24)?;
                let setting = SettingId::new(target)?;
                let schema = match kind {
                    1 if maximum_length == 0 && minimum == 0 && maximum == 0 => {
                        SettingSchema::boolean(setting, object)?
                    }
                    2 if maximum_length == 0 => {
                        SettingSchema::unsigned(setting, object, minimum, maximum)?
                    }
                    3 if minimum == 0 && maximum == 0 => {
                        SettingSchema::bytes(setting, object, maximum_length)?
                    }
                    _ => return Err(ConfigError::NonCanonical),
                };
                Ok(Self::AdmitSchema {
                    request_id,
                    root: authority,
                    schema,
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
        let mut capabilities = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
        let count = message.capability_count();
        for (slot, capability) in capabilities.iter_mut().zip(message.capabilities()) {
            *slot = capability;
        }
        Self::decode_envelope(message.payload(), &capabilities[..count])
    }

    /// Decodes the exact payload and opaque receiver handles returned by the
    /// buffered CPL3 receive ABI. The handles remain inert until an authorizer
    /// asks the kernel to validate exact generation, rights, and object.
    pub fn decode_envelope(
        payload: &[u8],
        capabilities: &[Capability],
    ) -> Result<Self, ConfigError> {
        let mut request = Self::decode(payload)?;
        match &mut request {
            Self::Read { capability, .. } => {
                if payload[32..40].iter().any(|byte| *byte != 0) || capabilities.len() != 1 {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                *capability = capabilities
                    .iter()
                    .copied()
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
            }
            Self::Commit {
                root, transaction, ..
            } => {
                if payload[32..40].iter().any(|byte| *byte != 0)
                    || capabilities.len() != transaction.count + 1
                {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                let mut authorities = capabilities.iter().copied();
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
            Self::AdmitSchema { root, .. } => {
                if payload[32..40].iter().any(|byte| *byte != 0) || capabilities.len() != 1 {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                *root = capabilities[0];
            }
        }
        Ok(request)
    }
}

pub fn encode_schema_message_request(
    request_id: u64,
    schema: SettingSchema,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    encode_schema_request(request_id, Capability::from_token(0), schema, output)
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

pub fn encode_schema_request(
    request_id: u64,
    root: Capability,
    schema: SettingSchema,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    let length = CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES;
    if request_id == 0 {
        return Err(ConfigError::NonCanonical);
    }
    if output.len() < length {
        return Err(ConfigError::Truncated);
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 3)?;
    write_u16(output, 8, length as u16)?;
    write_u64(output, 16, request_id)?;
    write_u64(output, 32, root.token())?;
    write_u32(output, 40, schema.setting.get())?;
    write_u64(output, CONFIG_REQUEST_HEADER_BYTES, schema.object.0)?;
    match schema.constraint {
        Constraint::Bool => output[CONFIG_REQUEST_HEADER_BYTES + 8] = 1,
        Constraint::U64 { minimum, maximum } => {
            output[CONFIG_REQUEST_HEADER_BYTES + 8] = 2;
            write_u64(output, CONFIG_REQUEST_HEADER_BYTES + 16, minimum)?;
            write_u64(output, CONFIG_REQUEST_HEADER_BYTES + 24, maximum)?;
        }
        Constraint::Bytes { maximum_length } => {
            output[CONFIG_REQUEST_HEADER_BYTES + 8] = 3;
            output[CONFIG_REQUEST_HEADER_BYTES + 9] = maximum_length;
        }
    }
    Ok(length)
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
    A: CapabilityAuthorizer + ?Sized,
>(
    service: &mut ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    message: &Message,
    output: &mut [u8; CONFIG_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let mut capabilities_wire = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
    let count = message.capability_count();
    for (slot, capability) in capabilities_wire.iter_mut().zip(message.capabilities()) {
        *slot = capability;
    }
    dispatch_configuration_envelope(
        service,
        capabilities,
        message.payload(),
        &capabilities_wire[..count],
        output,
    )
}

pub fn dispatch_configuration_envelope<
    const SETTINGS: usize,
    const AUDIT: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    service: &mut ConfigurationService<SETTINGS, AUDIT>,
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; CONFIG_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let request = ConfigurationRequest::decode_envelope(payload, capabilities)?;
    let response = match request {
        ConfigurationRequest::Read {
            request_id,
            setting,
            capability,
        } => match service.read(authorizer, capability, setting) {
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
        } => match service.commit(authorizer, root, &transaction) {
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
        ConfigurationRequest::AdmitSchema {
            request_id,
            root,
            schema,
        } => match service.admit_schema(authorizer, root, schema) {
            Ok(()) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision: service.revision(),
                setting: Some(schema.setting()),
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
}

impl SupervisionRequest {
    pub fn encode(self, output: &mut [u8; SUPERVISION_REQUEST_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; SUPERVISION_REQUEST_BYTES];
        output[..4].copy_from_slice(&SUPERVISION_REQUEST_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.operation as u16)?;
        write_u16(output, 8, SUPERVISION_REQUEST_BYTES as u16)?;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.service.token())?;
        write_u64(output, 32, self.capability.token())
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != SUPERVISION_REQUEST_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != SUPERVISION_REQUEST_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[10..16].iter().any(|byte| *byte != 0)
            || input[40..48].iter().any(|byte| *byte != 0)
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
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        Ok(Self {
            operation,
            request_id,
            service: ServiceId::from_token(read_u64(input, 24)?),
            capability: Capability::from_token(read_u64(input, 32)?),
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

/// Dispatches the query-only portion of the canonical supervision protocol at
/// the userspace service boundary. Restart remains a distinct trusted kernel
/// transition because its launch context cannot come from request bytes.
pub fn dispatch_supervision_query_envelope<A: ServiceStateAuthorizer + ?Sized>(
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let message =
        Message::new(payload, capabilities).map_err(|_| ConfigError::InvalidAuthorityEnvelope)?;
    let request = SupervisionRequest::decode_message(&message)?;
    if request.operation != SupervisionOperation::Query {
        return Err(ConfigError::InvalidProtocol);
    }
    let (status, state) = match authorizer.query_state(request.capability, request.service) {
        Ok(state) => (ResponseStatus::Ok, state.into()),
        Err(_) => (ResponseStatus::Rejected, SupervisionState::Exited),
    };
    SupervisionResponse {
        request_id: request.request_id,
        status,
        service: request.service,
        state,
        detail: 0,
    }
    .encode(output)
}

pub fn dispatch_supervision_restart_envelope<A: ServiceRestartAuthorizer + ?Sized>(
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let message =
        Message::new(payload, capabilities).map_err(|_| ConfigError::InvalidAuthorityEnvelope)?;
    let request = SupervisionRequest::decode_message(&message)?;
    if request.operation != SupervisionOperation::Restart {
        return Err(ConfigError::InvalidProtocol);
    }
    let (status, service, state) =
        match authorizer.restart_service(request.capability, request.service) {
            Ok(replacement) => (ResponseStatus::Ok, replacement, SupervisionState::Running),
            Err(_) => (
                ResponseStatus::Rejected,
                request.service,
                SupervisionState::Exited,
            ),
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
    now: u64,
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
            now,
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

fn checkpoint_digest(input: &[u8]) -> [u8; CONFIG_CHECKPOINT_DIGEST_BYTES] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..CONFIG_CHECKPOINT_DIGEST_OFFSET]);
    digest.update(&[0; CONFIG_CHECKPOINT_DIGEST_BYTES]);
    digest.update(&input[CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES..]);
    digest.finalize()
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
    use mrml_storage::{
        CowMetadataImage, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan,
        ExtentRecord, FileReadBackend, FileWriteBackend, StorageObjectId, StorageObjectKind,
        StorageRights, StorageTransactionId, Superblock, VolumeHeader, VolumeId,
    };

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
        wire[12] = 0;
        wire[40..48].copy_from_slice(&99u64.to_le_bytes());
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
            0,
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
    fn supervision_query_envelope_uses_only_delivered_read_authority() {
        struct QueryAuthorizer {
            capability: Capability,
            service: ServiceId,
        }

        impl ServiceStateAuthorizer for QueryAuthorizer {
            fn query_state(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                if capability == self.capability && service == self.service {
                    Ok(ServiceState::Running)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((8u64 << 32) | 3);
        let service = ServiceId::from_token((4u64 << 32) | 2);
        let authorizer = QueryAuthorizer {
            capability,
            service,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 52,
            service,
            capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_query_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 52,
                status: ResponseStatus::Ok,
                service,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_query_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &forged, &[capability], &mut response,),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let wrong = Capability::from_token((9u64 << 32) | 3);
        dispatch_supervision_query_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        let rejected = SupervisionResponse::decode(&response).unwrap();
        assert_eq!(rejected.status, ResponseStatus::Rejected);
        assert_eq!(rejected.state, SupervisionState::Exited);
        assert_eq!(rejected.detail, 0);
    }

    #[test]
    fn userspace_supervision_dispatch_refuses_restart_requests() {
        struct RejectAll;
        impl ServiceStateAuthorizer for RejectAll {
            fn query_state(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                panic!("restart must be rejected before querying the kernel")
            }
        }

        let capability = Capability::from_token((2u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 53,
            service: ServiceId::from_token((3u64 << 32) | 1),
            capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_query_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn supervision_restart_envelope_uses_only_delivered_control_authority() {
        struct RestartAuthorizer {
            capability: Capability,
            retired: ServiceId,
            replacement: ServiceId,
        }

        impl ServiceRestartAuthorizer for RestartAuthorizer {
            fn restart_service(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                if capability == self.capability && service == self.retired {
                    Ok(self.replacement)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((11u64 << 32) | 2);
        let retired = ServiceId::from_token((7u64 << 32) | 1);
        let replacement = ServiceId::from_token((7u64 << 32) | 2);
        let authorizer = RestartAuthorizer {
            capability,
            retired,
            replacement,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 54,
            service: retired,
            capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Ok,
                service: replacement,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_restart_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &forged,
                &[capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );

        let wrong = Capability::from_token((12u64 << 32) | 2);
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Rejected,
                service: retired,
                state: SupervisionState::Exited,
                detail: 0,
            })
        );
    }

    #[test]
    fn restart_dispatch_refuses_query_before_calling_the_authorizer() {
        struct RejectAll;
        impl ServiceRestartAuthorizer for RejectAll {
            fn restart_service(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                panic!("query must be rejected before requesting a restart")
            }
        }

        let capability = Capability::from_token((13u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 55,
            service: ServiceId::from_token((8u64 << 32) | 1),
            capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_restart_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
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

    #[test]
    fn schema_admission_uses_only_root_authority_from_the_message_envelope() {
        let root_object = ObjectId(10);
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let mut service = ConfigurationService::<2, 2>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_schema_message_request(41, schema, &mut wire).unwrap();
        assert_eq!(length, CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES);
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&wire[..length], &[root]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&message),
            Ok(ConfigurationRequest::AdmitSchema {
                request_id: 41,
                root,
                schema,
            })
        );
        let mut response = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response)
            .unwrap();
        assert_eq!(service.setting_count(), 1);
        assert_eq!(
            ConfigurationResponse::decode(&response).unwrap(),
            ConfigurationResponse {
                request_id: 41,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(schema.setting()),
                value: None,
            }
        );

        let missing = Message::new(&wire[..length], &[]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&missing),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        wire[CONFIG_REQUEST_HEADER_BYTES + 10] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn schema_admission_rejects_aliases_capacity_and_post_commit_mutation() {
        let root_object = ObjectId(20);
        let setting = SettingId::new(1).unwrap();
        let schema = SettingSchema::boolean(setting, ObjectId(21)).unwrap();
        let mut service = ConfigurationService::<1, 1>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let write = capabilities.insert(ObjectId(21), Rights::WRITE).unwrap();
        service.admit_schema(&capabilities, root, schema).unwrap();
        assert_eq!(
            service.admit_schema(&capabilities, root, schema),
            Err(ConfigError::DuplicateObject)
        );
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                write,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &transaction).unwrap();
        assert_eq!(
            service.admit_schema(
                &capabilities,
                root,
                SettingSchema::boolean(SettingId::new(2).unwrap(), ObjectId(22)).unwrap(),
            ),
            Err(ConfigError::SchemaFrozen)
        );
    }

    #[test]
    fn checkpoint_round_trip_preserves_schema_values_revisions_and_audit_window() {
        let (mut service, capabilities, root, enabled, limit) = fixture();
        let mut first = ConfigTransaction::<2>::new(0);
        first
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        first
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        service.commit(&capabilities, root, &first).unwrap();
        let mut second = ConfigTransaction::<1>::new(1);
        second
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(false),
            ))
            .unwrap();
        service.commit(&capabilities, root, &second).unwrap();

        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut bytes)
            .unwrap();
        assert_eq!(checkpoint.length, 368);
        let recovered = ConfigurationService::<3, 2>::recover_checkpoint(
            &capabilities,
            root,
            &bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 2);
        assert_eq!(recovered.setting_count(), 2);
        assert_eq!(
            recovered
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(false)
        );
        assert_eq!(
            recovered
                .read(&capabilities, limit, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 2).unwrap(),
            Some(AuditEvent {
                sequence: 2,
                revision: 1,
                setting: SettingId::new(2).unwrap(),
            })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 2,
                setting: SettingId::new(1).unwrap(),
            })
        );
    }

    #[test]
    fn checkpoint_recovery_rejects_corruption_stale_digest_capacity_and_hidden_data() {
        let (service, capabilities, root, enabled, _) = fixture();
        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut bytes)
            .unwrap();
        let input = &mut bytes[..checkpoint.length];
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(
                &capabilities,
                root,
                input,
                checkpoint.digest,
            ),
            Err(ConfigError::InvalidCheckpoint)
        ));

        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 1;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::InvalidCheckpoint)
        ));
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 0;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<1, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::Capacity)
        ));
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, enabled, input, digest,),
            Err(ConfigError::Unauthorized(_))
        ));
    }

    const STABLE_BLOCK_BYTES: usize = 4096;

    fn stable_volume() -> VolumeId {
        VolumeId::new([0x51; 16]).unwrap()
    }

    fn stable_header() -> VolumeHeader {
        VolumeHeader::new(stable_volume(), STABLE_BLOCK_BYTES as u32, 100, 1, 2).unwrap()
    }

    fn stable_object(local: u64) -> StorageObjectId {
        StorageObjectId::new(stable_volume(), local).unwrap()
    }

    fn stable_principal() -> StoragePrincipal {
        StoragePrincipal::new(7).unwrap()
    }

    fn stable_digest(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(bytes);
        digest.finalize()
    }

    struct StableBackend {
        bytes: [u8; STABLE_BLOCK_BYTES],
        staged: usize,
        flushed: usize,
        reads: usize,
        fail_read: bool,
        corrupt_read: bool,
    }

    unsafe impl FileWriteBackend for StableBackend {
        type Error = u8;

        fn stage_new_extent(
            &mut self,
            file: StorageObjectId,
            old_generation: u64,
            old_length: u64,
            next: ExtentRecord,
            new_length: u64,
            patch_offset: u64,
            patch: &[u8],
        ) -> Result<(), Self::Error> {
            if file != stable_object(9)
                || old_generation != 1
                || old_length != 0
                || next.file() != file
                || next.metadata_generation() != 2
                || next.physical_block() != Some(10)
                || next.block_count() != 1
                || patch_offset != 0
                || usize::try_from(new_length).ok() != Some(patch.len())
            {
                return Err(1);
            }
            self.bytes.fill(0);
            self.bytes[..patch.len()].copy_from_slice(patch);
            if next.content_digest() != stable_digest(&self.bytes) {
                return Err(2);
            }
            self.staged += 1;
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            let length = usize::try_from(length).map_err(|_| 3)?;
            if file != stable_object(9)
                || generation != 2
                || length > self.bytes.len()
                || content_digest != stable_digest(&self.bytes[..length])
            {
                return Err(3);
            }
            self.flushed += 1;
            Ok(())
        }
    }

    unsafe impl FileReadBackend for StableBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads += 1;
            if self.fail_read {
                return Err(4);
            }
            if record.file() != stable_object(9)
                || record.metadata_generation() != 2
                || record.content_digest() != stable_digest(&self.bytes)
            {
                return Err(5);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 5)?;
            let end = start.checked_add(output.len()).ok_or(5)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(5)?);
            if self.corrupt_read && !output.is_empty() {
                output[0] ^= 1;
            }
            Ok(())
        }
    }

    struct PublicationBackend;

    unsafe impl CowPublicationBackend for PublicationBackend {
        type Error = ();

        fn verify_new_metadata(&mut self, _: CowMetadataWrite) -> Result<(), Self::Error> {
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            (block == 2).then_some(()).ok_or(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn stable_layout(
        checkpoint: &[u8],
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        [CowMetadataImage; 2],
    ) {
        let header = stable_header();
        let object = stable_object(9);
        let current_extents = ExtentMap::<0>::build(header, object, 1, 0, &[]).unwrap();
        let current = FileState::new(object, 1, 0, current_extents).unwrap();
        let mut block = [0; STABLE_BLOCK_BYTES];
        block[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object, 2, 0, 1, 10, stable_digest(&block)).unwrap();
        let next = ExtentMap::build(header, object, 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object,
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            stable_digest(checkpoint),
        )
        .unwrap();
        let mut encoded_metadata = [0; STABLE_BLOCK_BYTES];
        metadata.encode(
            (&mut encoded_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut encoded_extents = [0; STABLE_BLOCK_BYTES];
        record.encode(
            (&mut encoded_extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        (
            current,
            next,
            metadata,
            [
                CowMetadataImage::new(
                    MetadataPointer::new(21, 1).unwrap(),
                    stable_digest(&encoded_metadata),
                ),
                CowMetadataImage::new(
                    MetadataPointer::new(20, 1).unwrap(),
                    stable_digest(&encoded_extents),
                ),
            ],
        )
    }

    fn publication_plan(images: [CowMetadataImage; 2]) -> CowPublicationPlan<4> {
        let header = stable_header();
        let root = stable_object(1);
        let active = Superblock::new(
            header,
            1,
            0,
            root,
            MetadataPointer::new(30, 1).unwrap(),
            MetadataPointer::new(31, 1).unwrap(),
        )
        .unwrap();
        let root_write =
            CowMetadataWrite::new(MetadataPointer::new(40, 1).unwrap(), 2, [0x40; 32]).unwrap();
        let allocation_write =
            CowMetadataWrite::new(MetadataPointer::new(41, 1).unwrap(), 2, [0x41; 32]).unwrap();
        CowPublicationPlan::build(
            header,
            1,
            active,
            root,
            root_write.pointer(),
            allocation_write.pointer(),
            &[
                images[0].bind(2).unwrap(),
                images[1].bind(2).unwrap(),
                root_write,
                allocation_write,
            ],
            &[
                MetadataPointer::new(30, 1).unwrap(),
                MetadataPointer::new(31, 1).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn stable_checkpoint_requires_both_capabilities_and_one_use_publication_receipt() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        let mut update = ConfigTransaction::<1>::new(0);
        update
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &update).unwrap();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut expected)
            .unwrap();
        let (current, next, metadata, images) = stable_layout(&expected[..checkpoint.length]);
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        let prepared = prepare_stable_configuration(
            &service,
            &capabilities,
            root,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        assert_eq!(prepared.checkpoint(), checkpoint);
        assert_eq!(prepared.revision(), 1);
        assert_eq!((backend.staged, backend.flushed), (1, 1));

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(70).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&mut receipt).unwrap();
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(stable.file().generation(), 2);
        assert_eq!(stable.checkpoint(), checkpoint);

        let mut recovered_bytes = [0xa5; 512];
        let recovered = recover_stable_configuration::<3, 2, _, _, _, _>(
            stable.file(),
            &authority,
            file,
            stable_principal(),
            stable.file().generation(),
            &capabilities,
            root,
            &mut recovered_bytes,
            &mut backend,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 1);
        assert_eq!(
            recovered
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );
    }

    #[test]
    fn stable_checkpoint_rejects_wrong_authority_binding_corruption_and_io_uncertainty() {
        let (service, capabilities, root, enabled, _) = fixture();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut expected)
            .unwrap();
        let (current, next, mut metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let mut denied_authority = StorageAuthorityTable::<1>::new();
        let denied = denied_authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::WRITE,
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &denied_authority,
                denied,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Write(FileWriteError::Authority(
                _
            )))
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, _, _) = stable_layout(&expected[..checkpoint.length]);
        metadata = FileMetadata::new(
            stable_header(),
            stable_object(9),
            2,
            checkpoint.length as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            [0xff; 32],
        )
        .unwrap();
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let (_, unauthorized_next, unauthorized_metadata, _) =
            stable_layout(&expected[..checkpoint.length]);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                enabled,
                &current,
                &authority,
                file,
                stable_principal(),
                unauthorized_next,
                unauthorized_metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::WrongObject
            ))
        ));
        assert_eq!(backend.staged, 0);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &authority,
                file,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let prepared = prepare_stable_configuration(
            &service,
            &capabilities,
            root,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(71).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let (_, _, _, images) = stable_layout(&expected[..checkpoint.length]);
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&mut receipt).unwrap();

        let mut recovered_bytes = [0xa5; 512];
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation() - 1,
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.reads, 0);

        backend.corrupt_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::InvalidCheckpoint
            ))
        ));
        backend.corrupt_read = false;
        backend.fail_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Read(FileReadError::Backend(4)))
        ));
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));
    }
}
