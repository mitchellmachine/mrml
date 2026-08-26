use crate::SystemGenerationView;

const MAGIC: [u8; 8] = *b"MRMLRI1\0";
const HEADER_BYTES: usize = 24;
const RECORD_BYTES: usize = 88;
pub const MAX_RUNTIME_INVENTORY_PACKAGES: usize = 256;
pub const MAX_RUNTIME_REASON_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeIsolationClass {
    MicrovmEligible = 1,
    HostSubstrateRequired = 2,
    BootOnly = 3,
    RecoveryOnly = 4,
    UnsupportedBlocker = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeIsolationPlacement {
    InProcess = 1,
    NativeProcess = 2,
    NativeService = 3,
    Microvm = 4,
    Platform = 5,
}

impl RuntimeIsolationPlacement {
    pub const fn bit(self) -> u8 {
        1 << (self as u8 - 1)
    }

    const fn rank(self) -> Option<u8> {
        match self {
            Self::InProcess => Some(0),
            Self::NativeProcess | Self::NativeService => Some(1),
            Self::Microvm => Some(2),
            Self::Platform => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeInventoryRecord<'a> {
    pub package_id: &'a str,
    pub version: u64,
    pub artifact_digest: &'a [u8; 64],
    pub class: RuntimeIsolationClass,
    pub must_run: bool,
    pub preferred: RuntimeIsolationPlacement,
    pub minimum: RuntimeIsolationPlacement,
    pub maximum: RuntimeIsolationPlacement,
    pub supported: u8,
    pub reason: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInventoryError {
    Format,
    Generation,
    PackageCount,
    PackageIdentity,
    PackageOrder,
    PackageVersion,
    ArtifactDigest,
    Class,
    Placement,
    Reason,
    Reserved,
    Truncated,
    TrailingBytes,
    OutputTooSmall,
    LengthOverflow,
    SystemGenerationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeInventoryView<'a> {
    bytes: &'a [u8],
    generation: u64,
    package_count: u32,
}

impl<'a> RuntimeInventoryView<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RuntimeInventoryError> {
        if bytes.len() < HEADER_BYTES || bytes[..8] != MAGIC {
            return Err(RuntimeInventoryError::Format);
        }
        let generation = read_u64(bytes, 8)?;
        let package_count = read_u32(bytes, 16)?;
        if generation == 0 {
            return Err(RuntimeInventoryError::Generation);
        }
        if package_count == 0 || package_count as usize > MAX_RUNTIME_INVENTORY_PACKAGES {
            return Err(RuntimeInventoryError::PackageCount);
        }
        if read_u32(bytes, 20)? != 0 {
            return Err(RuntimeInventoryError::Reserved);
        }
        let mut offset = HEADER_BYTES;
        let mut previous = None;
        for _ in 0..package_count {
            let (record, next) = decode_record(bytes, offset)?;
            if previous.is_some_and(|identity| identity >= record.package_id) {
                return Err(RuntimeInventoryError::PackageOrder);
            }
            previous = Some(record.package_id);
            offset = next;
        }
        if offset != bytes.len() {
            return Err(RuntimeInventoryError::TrailingBytes);
        }
        Ok(Self {
            bytes,
            generation,
            package_count,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn package_count(self) -> u32 {
        self.package_count
    }

    pub fn records(self) -> RuntimeInventoryRecords<'a> {
        RuntimeInventoryRecords {
            bytes: self.bytes,
            remaining: self.package_count,
            offset: HEADER_BYTES,
        }
    }

    /// Requires an exact one-for-one identity/version/digest match with the
    /// canonical SystemGeneration. A subset or independently substituted
    /// runtime catalog can never classify the active release.
    pub fn validate_system_generation(
        self,
        generation: SystemGenerationView<'_>,
    ) -> Result<(), RuntimeInventoryError> {
        if self.generation != generation.generation()
            || self.package_count != generation.package_count()
        {
            return Err(RuntimeInventoryError::SystemGenerationMismatch);
        }
        for (runtime, package) in self.records().zip(generation.packages()) {
            if runtime.package_id != package.package_id()
                || runtime.version != package.version()
                || runtime.artifact_digest != package.artifact_digest()
            {
                return Err(RuntimeInventoryError::SystemGenerationMismatch);
            }
        }
        Ok(())
    }
}

pub struct RuntimeInventoryRecords<'a> {
    bytes: &'a [u8],
    remaining: u32,
    offset: usize,
}

impl<'a> Iterator for RuntimeInventoryRecords<'a> {
    type Item = RuntimeInventoryRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (record, next) = decode_record(self.bytes, self.offset).ok()?;
        self.offset = next;
        self.remaining -= 1;
        Some(record)
    }
}

pub fn encode_runtime_inventory(
    generation: u64,
    records: &[RuntimeInventoryRecord<'_>],
    output: &mut [u8],
) -> Result<usize, RuntimeInventoryError> {
    if generation == 0 {
        return Err(RuntimeInventoryError::Generation);
    }
    if records.is_empty() || records.len() > MAX_RUNTIME_INVENTORY_PACKAGES {
        return Err(RuntimeInventoryError::PackageCount);
    }
    let mut previous = None;
    let mut required = HEADER_BYTES;
    for record in records {
        validate_record(record)?;
        if previous.is_some_and(|identity| identity >= record.package_id) {
            return Err(RuntimeInventoryError::PackageOrder);
        }
        previous = Some(record.package_id);
        required = required
            .checked_add(RECORD_BYTES)
            .and_then(|length| length.checked_add(record.package_id.len()))
            .and_then(|length| length.checked_add(record.reason.len()))
            .ok_or(RuntimeInventoryError::LengthOverflow)?;
    }
    if output.len() < required {
        return Err(RuntimeInventoryError::OutputTooSmall);
    }
    output[..required].fill(0);
    output[..8].copy_from_slice(&MAGIC);
    output[8..16].copy_from_slice(&generation.to_le_bytes());
    output[16..20].copy_from_slice(&(records.len() as u32).to_le_bytes());
    let mut offset = HEADER_BYTES;
    for record in records {
        output[offset..offset + 2].copy_from_slice(&(record.package_id.len() as u16).to_le_bytes());
        output[offset + 2..offset + 4].copy_from_slice(&(record.reason.len() as u16).to_le_bytes());
        output[offset + 4] = record.class as u8;
        output[offset + 5] = u8::from(record.must_run);
        output[offset + 6] = record.preferred as u8;
        output[offset + 7] = record.minimum as u8;
        output[offset + 8] = record.maximum as u8;
        output[offset + 9] = record.supported;
        output[offset + 16..offset + 24].copy_from_slice(&record.version.to_le_bytes());
        output[offset + 24..offset + RECORD_BYTES].copy_from_slice(record.artifact_digest);
        let id_start = offset + RECORD_BYTES;
        let reason_start = id_start + record.package_id.len();
        output[id_start..reason_start].copy_from_slice(record.package_id.as_bytes());
        output[reason_start..reason_start + record.reason.len()]
            .copy_from_slice(record.reason.as_bytes());
        offset = reason_start + record.reason.len();
    }
    Ok(required)
}

fn decode_record(
    bytes: &[u8],
    offset: usize,
) -> Result<(RuntimeInventoryRecord<'_>, usize), RuntimeInventoryError> {
    let header = bytes
        .get(offset..offset + RECORD_BYTES)
        .ok_or(RuntimeInventoryError::Truncated)?;
    if header[10..16].iter().any(|byte| *byte != 0) {
        return Err(RuntimeInventoryError::Reserved);
    }
    let id_length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let reason_length = u16::from_le_bytes([header[2], header[3]]) as usize;
    let end = offset
        .checked_add(RECORD_BYTES)
        .and_then(|value| value.checked_add(id_length))
        .and_then(|value| value.checked_add(reason_length))
        .ok_or(RuntimeInventoryError::LengthOverflow)?;
    let package_id = core::str::from_utf8(
        bytes
            .get(offset + RECORD_BYTES..offset + RECORD_BYTES + id_length)
            .ok_or(RuntimeInventoryError::Truncated)?,
    )
    .map_err(|_| RuntimeInventoryError::PackageIdentity)?;
    let reason = core::str::from_utf8(
        bytes
            .get(offset + RECORD_BYTES + id_length..end)
            .ok_or(RuntimeInventoryError::Truncated)?,
    )
    .map_err(|_| RuntimeInventoryError::Reason)?;
    let digest: &[u8; 64] = header[24..88]
        .try_into()
        .map_err(|_| RuntimeInventoryError::Truncated)?;
    let record = RuntimeInventoryRecord {
        package_id,
        version: u64::from_le_bytes(header[16..24].try_into().unwrap()),
        artifact_digest: digest,
        class: decode_class(header[4])?,
        must_run: match header[5] {
            0 => false,
            1 => true,
            _ => return Err(RuntimeInventoryError::Reserved),
        },
        preferred: decode_placement(header[6])?,
        minimum: decode_placement(header[7])?,
        maximum: decode_placement(header[8])?,
        supported: header[9],
        reason,
    };
    validate_record(&record)?;
    Ok((record, end))
}

fn validate_record(record: &RuntimeInventoryRecord<'_>) -> Result<(), RuntimeInventoryError> {
    if record.package_id.is_empty()
        || record.package_id.len() > 255
        || record
            .package_id
            .bytes()
            .any(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return Err(RuntimeInventoryError::PackageIdentity);
    }
    if record.version == 0 {
        return Err(RuntimeInventoryError::PackageVersion);
    }
    if record.artifact_digest.iter().all(|byte| *byte == 0) {
        return Err(RuntimeInventoryError::ArtifactDigest);
    }
    if record.reason.len() > MAX_RUNTIME_REASON_BYTES || record.reason.contains('\0') {
        return Err(RuntimeInventoryError::Reason);
    }
    let known = (1 << 5) - 1;
    if record.supported == 0
        || record.supported & !known != 0
        || record.supported & record.preferred.bit() == 0
        || record.supported & record.minimum.bit() == 0
        || record.supported & record.maximum.bit() == 0
    {
        return Err(RuntimeInventoryError::Placement);
    }
    let platform = RuntimeIsolationPlacement::Platform;
    if record.supported & platform.bit() != 0 {
        if record.supported != platform.bit()
            || record.preferred != platform
            || record.minimum != platform
            || record.maximum != platform
        {
            return Err(RuntimeInventoryError::Placement);
        }
    } else if record.minimum.rank() > record.preferred.rank()
        || record.preferred.rank() > record.maximum.rank()
    {
        return Err(RuntimeInventoryError::Placement);
    }
    match record.class {
        RuntimeIsolationClass::MicrovmEligible => {
            if record.supported & RuntimeIsolationPlacement::Microvm.bit() == 0
                || record.supported & RuntimeIsolationPlacement::Platform.bit() != 0
                || !record.reason.is_empty()
            {
                return Err(RuntimeInventoryError::Class);
            }
        }
        _ if record.reason.is_empty() => return Err(RuntimeInventoryError::Reason),
        _ => {}
    }
    Ok(())
}

fn decode_class(value: u8) -> Result<RuntimeIsolationClass, RuntimeInventoryError> {
    match value {
        1 => Ok(RuntimeIsolationClass::MicrovmEligible),
        2 => Ok(RuntimeIsolationClass::HostSubstrateRequired),
        3 => Ok(RuntimeIsolationClass::BootOnly),
        4 => Ok(RuntimeIsolationClass::RecoveryOnly),
        5 => Ok(RuntimeIsolationClass::UnsupportedBlocker),
        _ => Err(RuntimeInventoryError::Class),
    }
}

fn decode_placement(value: u8) -> Result<RuntimeIsolationPlacement, RuntimeInventoryError> {
    match value {
        1 => Ok(RuntimeIsolationPlacement::InProcess),
        2 => Ok(RuntimeIsolationPlacement::NativeProcess),
        3 => Ok(RuntimeIsolationPlacement::NativeService),
        4 => Ok(RuntimeIsolationPlacement::Microvm),
        5 => Ok(RuntimeIsolationPlacement::Platform),
        _ => Err(RuntimeInventoryError::Placement),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RuntimeInventoryError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(RuntimeInventoryError::Truncated)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RuntimeInventoryError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(RuntimeInventoryError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SystemGenerationDigestRecord, encode_system_generation};

    fn sample_records<'a>(digests: &'a [[u8; 64]; 2]) -> [RuntimeInventoryRecord<'a>; 2] {
        [
            RuntimeInventoryRecord {
                package_id: "org.mrml.app.shell",
                version: 4,
                artifact_digest: &digests[0],
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: true,
                preferred: RuntimeIsolationPlacement::NativeProcess,
                minimum: RuntimeIsolationPlacement::NativeProcess,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::NativeProcess.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
            RuntimeInventoryRecord {
                package_id: "org.mrml.system.kernel",
                version: 7,
                artifact_digest: &digests[1],
                class: RuntimeIsolationClass::BootOnly,
                must_run: true,
                preferred: RuntimeIsolationPlacement::Platform,
                minimum: RuntimeIsolationPlacement::Platform,
                maximum: RuntimeIsolationPlacement::Platform,
                supported: RuntimeIsolationPlacement::Platform.bit(),
                reason: "required before the VM substrate exists",
            },
        ]
    }

    #[test]
    fn catalog_round_trips_and_exact_matches_system_generation() {
        let digests = [[0x41; 64], [0x52; 64]];
        let records = sample_records(&digests);
        let mut inventory_bytes = [0; 1024];
        let length = encode_runtime_inventory(9, &records, &mut inventory_bytes).unwrap();
        let inventory = RuntimeInventoryView::decode(&inventory_bytes[..length]).unwrap();
        assert_eq!(inventory.generation(), 9);
        assert_eq!(inventory.records().count(), 2);

        let generation_records = [
            SystemGenerationDigestRecord {
                package_id: records[0].package_id,
                version: records[0].version,
                artifact_digest: records[0].artifact_digest,
            },
            SystemGenerationDigestRecord {
                package_id: records[1].package_id,
                version: records[1].version,
                artifact_digest: records[1].artifact_digest,
            },
        ];
        let mut generation_bytes = [0; 1024];
        let generation_length =
            encode_system_generation(9, &generation_records, &mut generation_bytes).unwrap();
        let generation =
            SystemGenerationView::decode(&generation_bytes[..generation_length]).unwrap();
        assert_eq!(inventory.validate_system_generation(generation), Ok(()));
    }

    #[test]
    fn catalog_rejects_substitution_ambiguity_and_invalid_classification() {
        let digests = [[0x41; 64], [0x52; 64]];
        let mut records = sample_records(&digests);
        records[0].class = RuntimeIsolationClass::UnsupportedBlocker;
        assert_eq!(
            encode_runtime_inventory(9, &records, &mut [0; 1024]),
            Err(RuntimeInventoryError::Reason)
        );
        records = sample_records(&digests);
        records[0].supported = RuntimeIsolationPlacement::NativeProcess.bit();
        assert_eq!(
            encode_runtime_inventory(9, &records, &mut [0; 1024]),
            Err(RuntimeInventoryError::Placement)
        );
        records = sample_records(&digests);
        records.swap(0, 1);
        assert_eq!(
            encode_runtime_inventory(9, &records, &mut [0; 1024]),
            Err(RuntimeInventoryError::PackageOrder)
        );

        let records = sample_records(&digests);
        let mut bytes = [0; 1024];
        let length = encode_runtime_inventory(9, &records, &mut bytes).unwrap();
        bytes[HEADER_BYTES + 10] = 1;
        assert_eq!(
            RuntimeInventoryView::decode(&bytes[..length]),
            Err(RuntimeInventoryError::Reserved)
        );

        let records = sample_records(&digests);
        let length = encode_runtime_inventory(9, &records, &mut bytes).unwrap();
        bytes[HEADER_BYTES + 4] = 9;
        assert_eq!(
            RuntimeInventoryView::decode(&bytes[..length]),
            Err(RuntimeInventoryError::Class)
        );
        bytes[HEADER_BYTES + 4] = RuntimeIsolationClass::MicrovmEligible as u8;
        assert_eq!(
            RuntimeInventoryView::decode(&bytes[..length - 1]),
            Err(RuntimeInventoryError::Truncated)
        );
    }

    #[test]
    fn catalog_rejects_generation_subset_and_artifact_substitution() {
        let digests = [[0x41; 64], [0x52; 64]];
        let runtime_records = sample_records(&digests);
        let mut inventory_bytes = [0; 1024];
        let inventory_length =
            encode_runtime_inventory(9, &runtime_records, &mut inventory_bytes).unwrap();
        let inventory = RuntimeInventoryView::decode(&inventory_bytes[..inventory_length]).unwrap();

        let substituted = [0x77; 64];
        let generation_records = [
            SystemGenerationDigestRecord {
                package_id: runtime_records[0].package_id,
                version: runtime_records[0].version,
                artifact_digest: runtime_records[0].artifact_digest,
            },
            SystemGenerationDigestRecord {
                package_id: runtime_records[1].package_id,
                version: runtime_records[1].version,
                artifact_digest: &substituted,
            },
        ];
        let mut generation_bytes = [0; 1024];
        let generation_length =
            encode_system_generation(9, &generation_records, &mut generation_bytes).unwrap();
        let generation =
            SystemGenerationView::decode(&generation_bytes[..generation_length]).unwrap();
        assert_eq!(
            inventory.validate_system_generation(generation),
            Err(RuntimeInventoryError::SystemGenerationMismatch)
        );

        let subset_length =
            encode_runtime_inventory(9, &runtime_records[..1], &mut inventory_bytes).unwrap();
        let subset = RuntimeInventoryView::decode(&inventory_bytes[..subset_length]).unwrap();
        assert_eq!(
            subset.validate_system_generation(generation),
            Err(RuntimeInventoryError::SystemGenerationMismatch)
        );
    }
}
