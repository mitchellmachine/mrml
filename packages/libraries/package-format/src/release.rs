use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512, lamport_verify};

pub const RELEASE_MAGIC: [u8; 16] = *b"MRML-RELEASE-v1\0";
pub const RELEASE_FORMAT_VERSION: u16 = 1;
pub const RELEASE_HEADER_BYTES: usize = 512;
pub const RELEASE_RECORD_BYTES: usize = 96;
pub const RELEASE_PACKAGE_COUNT: usize = 3;
pub const MAX_BOOT_RELEASE_BYTES: usize =
    RELEASE_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES;
const SIGNED: u16 = 1;
const RECORDS: usize = 176;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    Size,
    Format,
    Digest,
    Signature,
    Role,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BootPackageRole {
    Bootloader = 1,
    Kernel = 2,
    Configuration = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootPackageRecord {
    pub role: BootPackageRole,
    pub version: u64,
    pub package_digest: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootRelease<'a> {
    pub version: u64,
    pub digest: [u8; 64],
    pub key_id: [u8; 64],
    records: [BootPackageRecord; RELEASE_PACKAGE_COUNT],
    pub public_key: &'a [u8],
}

impl BootRelease<'_> {
    pub fn package(&self, role: BootPackageRole) -> BootPackageRecord {
        self.records[role as usize - 1]
    }

    pub fn binds_exact_package(
        &self,
        role: BootPackageRole,
        version: u64,
        package_bytes: &[u8],
    ) -> bool {
        let record = self.package(role);
        version != 0
            && record.version == version
            && record.package_digest == Sha3_512::digest(package_bytes)
    }
}

pub fn parse_release(
    bytes: &[u8],
    require_signature: bool,
) -> Result<BootRelease<'_>, ReleaseError> {
    if bytes.len() != MAX_BOOT_RELEASE_BYTES || bytes[..16] != RELEASE_MAGIC {
        return Err(ReleaseError::Size);
    }
    if u16_at(bytes, 16)? != RELEASE_FORMAT_VERSION
        || u32_at(bytes, 20)? as usize != RELEASE_HEADER_BYTES
        || u64_at(bytes, 32)? as usize != bytes.len()
        || u32_at(bytes, 40)? as usize != RELEASE_PACKAGE_COUNT
    {
        return Err(ReleaseError::Format);
    }
    let flags = u16_at(bytes, 18)?;
    if flags & !SIGNED != 0 || (require_signature && flags & SIGNED == 0) {
        return Err(ReleaseError::Signature);
    }
    let version = u64_at(bytes, 24)?;
    if version == 0 || bytes[44..48].iter().any(|byte| *byte != 0) {
        return Err(ReleaseError::Format);
    }
    let mut digest = [0; 64];
    digest.copy_from_slice(&bytes[48..112]);
    let mut key_id = [0; 64];
    key_id.copy_from_slice(&bytes[112..176]);
    if release_digest(&bytes[..RELEASE_HEADER_BYTES]) != digest {
        return Err(ReleaseError::Digest);
    }
    let mut records = [BootPackageRecord {
        role: BootPackageRole::Bootloader,
        version: 0,
        package_digest: [0; 64],
    }; RELEASE_PACKAGE_COUNT];
    for (index, expected) in [
        BootPackageRole::Bootloader,
        BootPackageRole::Kernel,
        BootPackageRole::Configuration,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = RECORDS + index * RELEASE_RECORD_BYTES;
        if bytes[offset] != expected as u8
            || bytes[offset + 1] != 1
            || bytes[offset + 2..offset + 8].iter().any(|byte| *byte != 0)
            || bytes[offset + 80..offset + RELEASE_RECORD_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ReleaseError::Role);
        }
        let record_version = u64_at(bytes, offset + 8)?;
        let mut package_digest = [0; 64];
        package_digest.copy_from_slice(&bytes[offset + 16..offset + 80]);
        if record_version == 0 || package_digest == [0; 64] {
            return Err(ReleaseError::Role);
        }
        records[index] = BootPackageRecord {
            role: expected,
            version: record_version,
            package_digest,
        };
    }
    if bytes[RECORDS + RELEASE_PACKAGE_COUNT * RELEASE_RECORD_BYTES..RELEASE_HEADER_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ReleaseError::Format);
    }
    let public = &bytes[RELEASE_HEADER_BYTES..RELEASE_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES];
    let signature = &bytes[RELEASE_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES..];
    if Sha3_512::digest(public) != key_id
        || lamport_verify(public, &release_statement(&digest), signature).is_err()
    {
        return Err(ReleaseError::Signature);
    }
    Ok(BootRelease {
        version,
        digest,
        key_id,
        records,
        public_key: public,
    })
}

pub fn release_digest(header: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(b"MRML-SYSTEM-RELEASE-CONTENT-v1\0");
    hash.update(&header[..48]);
    hash.update(&[0; 64]);
    hash.update(&header[112..]);
    hash.finalize()
}

pub fn release_statement(digest: &[u8; 64]) -> [u8; 97] {
    let mut statement = [0; 97];
    let prefix = b"MRML-SYSTEM-RELEASE-SIGNATURE-v1\0";
    statement[..prefix.len()].copy_from_slice(prefix);
    statement[prefix.len()..].copy_from_slice(digest);
    statement
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ReleaseError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ReleaseError::Format)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ReleaseError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ReleaseError::Format)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ReleaseError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ReleaseError::Format)
}
