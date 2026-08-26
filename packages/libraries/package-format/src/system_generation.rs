use mrml_crypto::Sha3_512;

const GENERATION_MAGIC: [u8; 8] = *b"MRMLSG2\0";
const GENERATION_HEADER_BYTES: usize = 24;
const PACKAGE_HEADER_BYTES: usize = 76;
pub const MAX_GENERATION_PACKAGES: usize = 256;
pub const MAX_PACKAGE_ID_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemGenerationDigestRecord<'a> {
    pub package_id: &'a str,
    pub version: u64,
    pub artifact_digest: &'a [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemGenerationDigestError {
    Generation,
    PackageCount,
    PackageIdentity,
    PackageOrder,
    PackageVersion,
    ArtifactDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemGenerationEncodingError {
    Invalid(SystemGenerationDigestError),
    OutputTooSmall,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemGenerationDecodeError {
    Format,
    Reserved,
    Generation,
    PackageCount,
    PackageIdentity,
    PackageOrder,
    PackageVersion,
    ArtifactDigest,
    Truncated,
    TrailingBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemGenerationPackage<'a> {
    package_id: &'a str,
    version: u64,
    artifact_digest: &'a [u8; 64],
}

impl<'a> SystemGenerationPackage<'a> {
    pub const fn package_id(self) -> &'a str {
        self.package_id
    }

    pub const fn version(self) -> u64 {
        self.version
    }

    pub const fn artifact_digest(self) -> &'a [u8; 64] {
        self.artifact_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemGenerationView<'a> {
    bytes: &'a [u8],
    generation: u64,
    package_count: u32,
}

impl<'a> SystemGenerationView<'a> {
    /// Validates a complete canonical `MRMLSG2` object and retains a zero-copy
    /// view. Package identities must be strictly ordered and every scalar,
    /// reserved byte, digest, and trailing byte is checked before publication.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, SystemGenerationDecodeError> {
        if bytes.len() < GENERATION_HEADER_BYTES || bytes[..8] != GENERATION_MAGIC {
            return Err(SystemGenerationDecodeError::Format);
        }
        let generation = read_u64(bytes, 8)?;
        if generation == 0 {
            return Err(SystemGenerationDecodeError::Generation);
        }
        let package_count = read_u32(bytes, 16)?;
        if package_count == 0 || package_count as usize > MAX_GENERATION_PACKAGES {
            return Err(SystemGenerationDecodeError::PackageCount);
        }
        if read_u32(bytes, 20)? != 0 {
            return Err(SystemGenerationDecodeError::Reserved);
        }

        let mut offset = GENERATION_HEADER_BYTES;
        let mut previous: Option<&str> = None;
        for _ in 0..package_count {
            let (package, next) = decode_package(bytes, offset)?;
            if previous.is_some_and(|identity| identity >= package.package_id) {
                return Err(SystemGenerationDecodeError::PackageOrder);
            }
            previous = Some(package.package_id);
            offset = next;
        }
        if offset != bytes.len() {
            return Err(SystemGenerationDecodeError::TrailingBytes);
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

    pub fn digest(self) -> [u8; 64] {
        let mut hash = Sha3_512::new();
        hash.update(self.bytes);
        hash.finalize()
    }

    pub fn packages(self) -> SystemGenerationPackages<'a> {
        SystemGenerationPackages {
            bytes: self.bytes,
            remaining: self.package_count,
            offset: GENERATION_HEADER_BYTES,
        }
    }

    pub fn package(self, package_id: &str) -> Option<SystemGenerationPackage<'a>> {
        self.packages()
            .take_while(|package| package.package_id <= package_id)
            .find(|package| package.package_id == package_id)
    }
}

pub struct SystemGenerationPackages<'a> {
    bytes: &'a [u8],
    remaining: u32,
    offset: usize,
}

impl<'a> Iterator for SystemGenerationPackages<'a> {
    type Item = SystemGenerationPackage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (package, next) = decode_package(self.bytes, self.offset).ok()?;
        self.offset = next;
        self.remaining -= 1;
        Some(package)
    }
}

/// Encodes the exact canonical bytes consumed by the runtime resolver. The
/// caller owns storage so early/runtime code needs no allocator.
pub fn encode_system_generation(
    generation: u64,
    records: &[SystemGenerationDigestRecord<'_>],
    output: &mut [u8],
) -> Result<usize, SystemGenerationEncodingError> {
    validate_records(generation, records).map_err(SystemGenerationEncodingError::Invalid)?;
    let required = records
        .iter()
        .try_fold(GENERATION_HEADER_BYTES, |total, record| {
            total
                .checked_add(PACKAGE_HEADER_BYTES)
                .and_then(|value| value.checked_add(record.package_id.len()))
                .ok_or(SystemGenerationEncodingError::LengthOverflow)
        })?;
    if output.len() < required {
        return Err(SystemGenerationEncodingError::OutputTooSmall);
    }
    output[..required].fill(0);
    output[..8].copy_from_slice(&GENERATION_MAGIC);
    output[8..16].copy_from_slice(&generation.to_le_bytes());
    output[16..20].copy_from_slice(&(records.len() as u32).to_le_bytes());
    let mut offset = GENERATION_HEADER_BYTES;
    for record in records {
        output[offset..offset + 2].copy_from_slice(&(record.package_id.len() as u16).to_le_bytes());
        output[offset + 4..offset + 12].copy_from_slice(&record.version.to_le_bytes());
        output[offset + 12..offset + 76].copy_from_slice(record.artifact_digest);
        offset += PACKAGE_HEADER_BYTES;
        let end = offset + record.package_id.len();
        output[offset..end].copy_from_slice(record.package_id.as_bytes());
        offset = end;
    }
    Ok(required)
}

/// Hashes the canonical `MRMLSG2` representation without allocating it.
/// Records must be the complete generation package set in strictly increasing
/// package-identity order; a subset is not an active SystemGeneration digest.
pub fn system_generation_digest(
    generation: u64,
    records: &[SystemGenerationDigestRecord<'_>],
) -> Result<[u8; 64], SystemGenerationDigestError> {
    validate_records(generation, records)?;
    let mut hash = Sha3_512::new();
    hash.update(&GENERATION_MAGIC);
    hash.update(&generation.to_le_bytes());
    hash.update(&(records.len() as u32).to_le_bytes());
    hash.update(&0u32.to_le_bytes());
    for record in records {
        hash.update(&(record.package_id.len() as u16).to_le_bytes());
        hash.update(&0u16.to_le_bytes());
        hash.update(&record.version.to_le_bytes());
        hash.update(record.artifact_digest);
        hash.update(record.package_id.as_bytes());
    }
    Ok(hash.finalize())
}

fn validate_records(
    generation: u64,
    records: &[SystemGenerationDigestRecord<'_>],
) -> Result<(), SystemGenerationDigestError> {
    if generation == 0 {
        return Err(SystemGenerationDigestError::Generation);
    }
    if records.is_empty() || records.len() > MAX_GENERATION_PACKAGES {
        return Err(SystemGenerationDigestError::PackageCount);
    }
    let mut previous = None;
    for record in records {
        if !package_identifier(record.package_id) {
            return Err(SystemGenerationDigestError::PackageIdentity);
        }
        if previous.is_some_and(|identity| identity >= record.package_id) {
            return Err(SystemGenerationDigestError::PackageOrder);
        }
        if record.version == 0 {
            return Err(SystemGenerationDigestError::PackageVersion);
        }
        if record.artifact_digest.iter().all(|byte| *byte == 0) {
            return Err(SystemGenerationDigestError::ArtifactDigest);
        }
        previous = Some(record.package_id);
    }

    Ok(())
}

fn decode_package(
    bytes: &[u8],
    offset: usize,
) -> Result<(SystemGenerationPackage<'_>, usize), SystemGenerationDecodeError> {
    let header_end = offset
        .checked_add(PACKAGE_HEADER_BYTES)
        .ok_or(SystemGenerationDecodeError::Truncated)?;
    let header = bytes
        .get(offset..header_end)
        .ok_or(SystemGenerationDecodeError::Truncated)?;
    let package_id_bytes = u16::from_le_bytes([header[0], header[1]]) as usize;
    if package_id_bytes == 0 || package_id_bytes > MAX_PACKAGE_ID_BYTES {
        return Err(SystemGenerationDecodeError::PackageIdentity);
    }
    if header[2..4] != [0; 2] {
        return Err(SystemGenerationDecodeError::Reserved);
    }
    let version = u64::from_le_bytes(
        header[4..12]
            .try_into()
            .map_err(|_| SystemGenerationDecodeError::Truncated)?,
    );
    if version == 0 {
        return Err(SystemGenerationDecodeError::PackageVersion);
    }
    let artifact_digest: &[u8; 64] = header[12..76]
        .try_into()
        .map_err(|_| SystemGenerationDecodeError::Truncated)?;
    if artifact_digest.iter().all(|byte| *byte == 0) {
        return Err(SystemGenerationDecodeError::ArtifactDigest);
    }
    let end = header_end
        .checked_add(package_id_bytes)
        .ok_or(SystemGenerationDecodeError::Truncated)?;
    let package_id = core::str::from_utf8(
        bytes
            .get(header_end..end)
            .ok_or(SystemGenerationDecodeError::Truncated)?,
    )
    .map_err(|_| SystemGenerationDecodeError::PackageIdentity)?;
    if !package_identifier(package_id) {
        return Err(SystemGenerationDecodeError::PackageIdentity);
    }
    Ok((
        SystemGenerationPackage {
            package_id,
            version,
            artifact_digest,
        },
        end,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SystemGenerationDecodeError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SystemGenerationDecodeError::Truncated)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SystemGenerationDecodeError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(SystemGenerationDecodeError::Truncated)
}

pub(crate) fn package_identifier(value: &str) -> bool {
    value.len() <= MAX_PACKAGE_ID_BYTES
        && value.starts_with("org.mrml.")
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_lowercase)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_digest_matches_canonical_generation_bytes() {
        let records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 8,
                artifact_digest: &[0x18; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 15,
                artifact_digest: &[0x2f; 64],
            },
        ];
        let digest = system_generation_digest(108, &records).unwrap();
        let mut bytes = [0u8; 256];
        let length = encode_system_generation(108, &records, &mut bytes).unwrap();
        let view = SystemGenerationView::decode(&bytes[..length]).unwrap();
        assert_ne!(digest, [0; 64]);
        assert_eq!(digest, system_generation_digest(108, &records).unwrap());
        assert_eq!(view.generation(), 108);
        assert_eq!(view.package_count(), 2);
        assert_eq!(view.digest(), digest);
        assert_eq!(view.package("org.mrml.zim").unwrap().version(), 8);
        assert_eq!(
            view.package("org.mrml.zstd").unwrap().artifact_digest(),
            &[0x2f; 64]
        );
    }

    #[test]
    fn incomplete_or_noncanonical_records_fail_closed() {
        assert_eq!(
            system_generation_digest(1, &[]),
            Err(SystemGenerationDigestError::PackageCount)
        );
        let reversed = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 1,
                artifact_digest: &[1; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 1,
                artifact_digest: &[2; 64],
            },
        ];
        assert_eq!(
            system_generation_digest(1, &reversed),
            Err(SystemGenerationDigestError::PackageOrder)
        );
    }

    #[test]
    fn canonical_view_rejects_truncation_reserved_bytes_order_and_trailing_data() {
        let records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 8,
                artifact_digest: &[0x18; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 15,
                artifact_digest: &[0x2f; 64],
            },
        ];
        let mut bytes = [0u8; 257];
        let length = encode_system_generation(108, &records, &mut bytes).unwrap();
        assert_eq!(
            SystemGenerationView::decode(&bytes[..length - 1]),
            Err(SystemGenerationDecodeError::Truncated)
        );
        bytes[20] = 1;
        assert_eq!(
            SystemGenerationView::decode(&bytes[..length]),
            Err(SystemGenerationDecodeError::Reserved)
        );
        bytes[20] = 0;
        bytes[length] = 1;
        assert_eq!(
            SystemGenerationView::decode(&bytes[..length + 1]),
            Err(SystemGenerationDecodeError::TrailingBytes)
        );

        let equal_length_records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.aaa",
                version: 1,
                artifact_digest: &[1; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.bbb",
                version: 2,
                artifact_digest: &[2; 64],
            },
        ];
        let length = encode_system_generation(9, &equal_length_records, &mut bytes).unwrap();
        let second_identity = GENERATION_HEADER_BYTES
            + PACKAGE_HEADER_BYTES
            + equal_length_records[0].package_id.len()
            + PACKAGE_HEADER_BYTES;
        bytes[second_identity..second_identity + "org.mrml.aaa".len()]
            .copy_from_slice(b"org.mrml.aaa");
        assert_eq!(
            SystemGenerationView::decode(&bytes[..length]),
            Err(SystemGenerationDecodeError::PackageOrder)
        );
    }
}
