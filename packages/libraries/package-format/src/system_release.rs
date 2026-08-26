use mrml_crypto::{
    LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512,
    lamport_public_key, lamport_sign, lamport_verify,
};

use crate::{
    InterfaceCatalogError, InterfaceCatalogView, SystemGenerationDecodeError, SystemGenerationView,
};

pub const SYSTEM_RELEASE_MAGIC: [u8; 16] = *b"MRML-SYSREL-v1\0\0";
pub const SYSTEM_RELEASE_FORMAT_VERSION: u16 = 1;
pub const SYSTEM_RELEASE_HEADER_BYTES: usize = 352;
pub const MAX_SYSTEM_RELEASE_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_SYSTEM_RELEASE_BYTES: usize = SYSTEM_RELEASE_HEADER_BYTES
    + MAX_SYSTEM_RELEASE_RECORD_BYTES
    + LAMPORT_PUBLIC_KEY_BYTES
    + LAMPORT_SIGNATURE_BYTES;
const SIGNED: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemReleaseError {
    Size,
    Format,
    Reserved,
    Generation(SystemGenerationDecodeError),
    Catalog(InterfaceCatalogError),
    GenerationMismatch,
    RecordDigest,
    ContentDigest,
    Signature,
    OutputTooSmall,
}

pub fn encode_system_release(
    generation_bytes: &[u8],
    catalog_bytes: &[u8],
    private: &[u8],
    output: &mut [u8],
) -> Result<usize, SystemReleaseError> {
    let generation =
        SystemGenerationView::decode(generation_bytes).map_err(SystemReleaseError::Generation)?;
    let catalog =
        InterfaceCatalogView::decode(catalog_bytes).map_err(SystemReleaseError::Catalog)?;
    if generation.generation() != catalog.generation() {
        return Err(SystemReleaseError::GenerationMismatch);
    }
    if private.len() != LAMPORT_PRIVATE_KEY_BYTES {
        return Err(SystemReleaseError::Signature);
    }
    let record_bytes = generation_bytes
        .len()
        .checked_add(catalog_bytes.len())
        .filter(|length| *length <= MAX_SYSTEM_RELEASE_RECORD_BYTES)
        .ok_or(SystemReleaseError::Size)?;
    let records_end = SYSTEM_RELEASE_HEADER_BYTES
        .checked_add(record_bytes)
        .ok_or(SystemReleaseError::Size)?;
    let total = records_end
        .checked_add(LAMPORT_PUBLIC_KEY_BYTES)
        .and_then(|end| end.checked_add(LAMPORT_SIGNATURE_BYTES))
        .filter(|total| *total <= MAX_SYSTEM_RELEASE_BYTES)
        .ok_or(SystemReleaseError::Size)?;
    if output.len() < total {
        return Err(SystemReleaseError::OutputTooSmall);
    }
    output[..total].fill(0);
    output[..16].copy_from_slice(&SYSTEM_RELEASE_MAGIC);
    output[16..18].copy_from_slice(&SYSTEM_RELEASE_FORMAT_VERSION.to_le_bytes());
    output[18..20].copy_from_slice(&SIGNED.to_le_bytes());
    output[20..24].copy_from_slice(&(SYSTEM_RELEASE_HEADER_BYTES as u32).to_le_bytes());
    output[24..32].copy_from_slice(&(total as u64).to_le_bytes());
    output[32..40].copy_from_slice(&(SYSTEM_RELEASE_HEADER_BYTES as u64).to_le_bytes());
    output[40..48].copy_from_slice(&(generation_bytes.len() as u64).to_le_bytes());
    output[48..56].copy_from_slice(
        &((SYSTEM_RELEASE_HEADER_BYTES + generation_bytes.len()) as u64).to_le_bytes(),
    );
    output[56..64].copy_from_slice(&(catalog_bytes.len() as u64).to_le_bytes());
    output[64..72].copy_from_slice(&generation.generation().to_le_bytes());
    output[72..136].copy_from_slice(&generation.digest());
    output[136..200].copy_from_slice(&catalog.digest());
    output[SYSTEM_RELEASE_HEADER_BYTES..SYSTEM_RELEASE_HEADER_BYTES + generation_bytes.len()]
        .copy_from_slice(generation_bytes);
    output[SYSTEM_RELEASE_HEADER_BYTES + generation_bytes.len()..records_end]
        .copy_from_slice(catalog_bytes);
    let public = &mut output[records_end..records_end + LAMPORT_PUBLIC_KEY_BYTES];
    lamport_public_key(private, public).map_err(|_| SystemReleaseError::Signature)?;
    let key_id = Sha3_512::digest(public);
    output[264..328].copy_from_slice(&key_id);
    let digest = system_release_content_digest(&output[..records_end])?;
    output[200..264].copy_from_slice(&digest);
    let signature = &mut output[records_end + LAMPORT_PUBLIC_KEY_BYTES..total];
    lamport_sign(private, &system_release_statement(&digest), signature)
        .map_err(|_| SystemReleaseError::Signature)?;
    parse_system_release(&output[..total])?;
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemReleaseArtifact<'a> {
    generation: SystemGenerationView<'a>,
    catalog: InterfaceCatalogView<'a>,
    content_digest: [u8; 64],
    key_id: [u8; 64],
}

impl<'a> SystemReleaseArtifact<'a> {
    pub const fn generation(self) -> SystemGenerationView<'a> {
        self.generation
    }

    pub const fn interface_catalog(self) -> InterfaceCatalogView<'a> {
        self.catalog
    }

    pub const fn content_digest(self) -> [u8; 64] {
        self.content_digest
    }

    pub const fn key_id(self) -> [u8; 64] {
        self.key_id
    }
}

pub fn parse_system_release(bytes: &[u8]) -> Result<SystemReleaseArtifact<'_>, SystemReleaseError> {
    if bytes.len()
        < SYSTEM_RELEASE_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES
        || bytes.len() > MAX_SYSTEM_RELEASE_BYTES
        || bytes[..16] != SYSTEM_RELEASE_MAGIC
    {
        return Err(SystemReleaseError::Size);
    }
    if read_u16(bytes, 16)? != SYSTEM_RELEASE_FORMAT_VERSION
        || read_u16(bytes, 18)? != SIGNED
        || read_u32(bytes, 20)? as usize != SYSTEM_RELEASE_HEADER_BYTES
        || read_u64(bytes, 24)? as usize != bytes.len()
        || read_u64(bytes, 32)? as usize != SYSTEM_RELEASE_HEADER_BYTES
    {
        return Err(SystemReleaseError::Format);
    }
    let generation_length =
        usize::try_from(read_u64(bytes, 40)?).map_err(|_| SystemReleaseError::Format)?;
    let catalog_offset =
        usize::try_from(read_u64(bytes, 48)?).map_err(|_| SystemReleaseError::Format)?;
    let catalog_length =
        usize::try_from(read_u64(bytes, 56)?).map_err(|_| SystemReleaseError::Format)?;
    let records_end = SYSTEM_RELEASE_HEADER_BYTES
        .checked_add(generation_length)
        .and_then(|end| end.checked_add(catalog_length))
        .ok_or(SystemReleaseError::Format)?;
    if generation_length == 0
        || catalog_length == 0
        || generation_length
            .checked_add(catalog_length)
            .is_none_or(|length| length > MAX_SYSTEM_RELEASE_RECORD_BYTES)
        || catalog_offset != SYSTEM_RELEASE_HEADER_BYTES + generation_length
        || records_end + LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES != bytes.len()
        || bytes[328..SYSTEM_RELEASE_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(SystemReleaseError::Format);
    }
    let generation_bytes = &bytes[SYSTEM_RELEASE_HEADER_BYTES..catalog_offset];
    let catalog_bytes = &bytes[catalog_offset..records_end];
    let generation =
        SystemGenerationView::decode(generation_bytes).map_err(SystemReleaseError::Generation)?;
    let catalog =
        InterfaceCatalogView::decode(catalog_bytes).map_err(SystemReleaseError::Catalog)?;
    if generation.generation() != catalog.generation()
        || generation.generation() != read_u64(bytes, 64)?
    {
        return Err(SystemReleaseError::GenerationMismatch);
    }
    if bytes[72..136] != generation.digest() || bytes[136..200] != catalog.digest() {
        return Err(SystemReleaseError::RecordDigest);
    }
    let mut content_digest = [0; 64];
    content_digest.copy_from_slice(&bytes[200..264]);
    if system_release_content_digest(&bytes[..records_end])? != content_digest {
        return Err(SystemReleaseError::ContentDigest);
    }
    let mut key_id = [0; 64];
    key_id.copy_from_slice(&bytes[264..328]);
    let public = &bytes[records_end..records_end + LAMPORT_PUBLIC_KEY_BYTES];
    let signature = &bytes[records_end + LAMPORT_PUBLIC_KEY_BYTES..];
    if Sha3_512::digest(public) != key_id
        || lamport_verify(
            public,
            &system_release_statement(&content_digest),
            signature,
        )
        .is_err()
    {
        return Err(SystemReleaseError::Signature);
    }
    Ok(SystemReleaseArtifact {
        generation,
        catalog,
        content_digest,
        key_id,
    })
}

pub fn system_release_content_digest(records: &[u8]) -> Result<[u8; 64], SystemReleaseError> {
    if records.len() < SYSTEM_RELEASE_HEADER_BYTES || records[..16] != SYSTEM_RELEASE_MAGIC {
        return Err(SystemReleaseError::Format);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"MRML-GENERAL-SYSTEM-RELEASE-CONTENT-v1\0");
    hash.update(&records[..200]);
    hash.update(&[0; 64]);
    hash.update(&records[264..]);
    Ok(hash.finalize())
}

pub fn system_release_statement(digest: &[u8; 64]) -> [u8; 105] {
    let mut statement = [0; 105];
    let prefix = b"MRML-GENERAL-SYSTEM-RELEASE-SIGNATURE-v1\0";
    statement[..prefix.len()].copy_from_slice(prefix);
    statement[prefix.len()..].copy_from_slice(digest);
    statement
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SystemReleaseError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SystemReleaseError::Format)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SystemReleaseError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SystemReleaseError::Format)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SystemReleaseError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(SystemReleaseError::Format)
}
