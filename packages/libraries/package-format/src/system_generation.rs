use mrml_crypto::Sha3_512;

const GENERATION_MAGIC: [u8; 8] = *b"MRMLSG2\0";
const MAX_GENERATION_PACKAGES: usize = 256;
const MAX_PACKAGE_ID_BYTES: usize = 255;

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

/// Hashes the canonical `MRMLSG2` representation without allocating it.
/// Records must be the complete generation package set in strictly increasing
/// package-identity order; a subset is not an active SystemGeneration digest.
pub fn system_generation_digest(
    generation: u64,
    records: &[SystemGenerationDigestRecord<'_>],
) -> Result<[u8; 64], SystemGenerationDigestError> {
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

fn package_identifier(value: &str) -> bool {
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
        assert_ne!(digest, [0; 64]);
        assert_eq!(digest, system_generation_digest(108, &records).unwrap());
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
}
