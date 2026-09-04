//! Canonical authenticated authority-generation records shared by the authority
//! service and offline backup verification.

use mrml_crypto::Sha256;
use mrml_runtime::{Text, Vector};

use crate::{RepositoryGeneration, RepositoryIdentity};

const MAGIC: &[u8; 8] = b"MRAGEN01";
const DOMAIN: &[u8] = b"MRML git authority repository generation v1\0";
const MAX_REPOSITORY_BYTES: usize = 255;
pub const AUTHORITY_GENERATION_RECORD_MAX_BYTES: usize = 8 + 2 + MAX_REPOSITORY_BYTES + 8 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityGenerationRecordError {
    Invalid,
}

pub fn authority_generation_record_name(repository: &RepositoryIdentity) -> Text {
    let mut digest = Sha256::new();
    digest.update(b"MRML authority repository catalog key v1\0");
    digest.update(repository.as_str().as_bytes());
    let digest = digest.finalize();
    let mut output = Text::new();
    use core::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output.push_str(".generation");
    output
}

pub fn encode_authority_generation_record(
    repository: &RepositoryIdentity,
    generation: RepositoryGeneration,
) -> Result<Vector<u8>, AuthorityGenerationRecordError> {
    let name = repository.as_str().as_bytes();
    if name.is_empty() || name.len() > MAX_REPOSITORY_BYTES || generation.0 == 0 {
        return Err(AuthorityGenerationRecordError::Invalid);
    }
    let mut output = Vector::with_capacity(8 + 2 + name.len() + 8 + 32)
        .map_err(|_| AuthorityGenerationRecordError::Invalid)?;
    append(&mut output, MAGIC)?;
    append(&mut output, &(name.len() as u16).to_be_bytes())?;
    append(&mut output, name)?;
    append(&mut output, &generation.0.to_be_bytes())?;
    let digest = checksum(&output);
    append(&mut output, &digest)?;
    Ok(output)
}

pub fn parse_authority_generation_record(
    input: &[u8],
    repository: &RepositoryIdentity,
) -> Result<RepositoryGeneration, AuthorityGenerationRecordError> {
    if input.len() < 8 + 2 + 1 + 8 + 32
        || input.len() > AUTHORITY_GENERATION_RECORD_MAX_BYTES
        || !input.starts_with(MAGIC)
    {
        return Err(AuthorityGenerationRecordError::Invalid);
    }
    let body_end = input.len() - 32;
    if checksum(&input[..body_end]) != input[body_end..] {
        return Err(AuthorityGenerationRecordError::Invalid);
    }
    let name_len = u16::from_be_bytes(
        input[8..10]
            .try_into()
            .map_err(|_| AuthorityGenerationRecordError::Invalid)?,
    ) as usize;
    let generation_offset = 10usize
        .checked_add(name_len)
        .ok_or(AuthorityGenerationRecordError::Invalid)?;
    if name_len == 0
        || name_len > MAX_REPOSITORY_BYTES
        || generation_offset.checked_add(8) != Some(body_end)
        || &input[10..generation_offset] != repository.as_str().as_bytes()
    {
        return Err(AuthorityGenerationRecordError::Invalid);
    }
    let generation = u64::from_be_bytes(
        input[generation_offset..body_end]
            .try_into()
            .map_err(|_| AuthorityGenerationRecordError::Invalid)?,
    );
    (generation != 0)
        .then_some(RepositoryGeneration(generation))
        .ok_or(AuthorityGenerationRecordError::Invalid)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    digest.finalize()
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), AuthorityGenerationRecordError> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| AuthorityGenerationRecordError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_and_binds_repository() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let encoded =
            encode_authority_generation_record(&repository, RepositoryGeneration(19)).unwrap();
        assert_eq!(
            parse_authority_generation_record(&encoded, &repository),
            Ok(RepositoryGeneration(19))
        );
        assert_eq!(authority_generation_record_name(&repository).len(), 75);
        assert!(authority_generation_record_name(&repository).ends_with(".generation"));
        let other = RepositoryIdentity::parse("owner/other").unwrap();
        assert_eq!(
            parse_authority_generation_record(&encoded, &other),
            Err(AuthorityGenerationRecordError::Invalid)
        );
    }

    #[test]
    fn tamper_truncation_and_zero_generation_fail_closed() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        assert!(encode_authority_generation_record(&repository, RepositoryGeneration(0)).is_err());
        let mut encoded =
            encode_authority_generation_record(&repository, RepositoryGeneration(1)).unwrap();
        encoded[12] ^= 1;
        assert!(parse_authority_generation_record(&encoded, &repository).is_err());
        encoded.pop();
        assert!(parse_authority_generation_record(&encoded, &repository).is_err());
    }
}
