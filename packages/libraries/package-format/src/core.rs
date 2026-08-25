use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512, lamport_verify};

pub const MAGIC: [u8; 16] = *b"MRML-PACKAGE-v1\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 256;
pub const ENTRY_BYTES: usize = 192;
pub const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_BOOT_PACKAGE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_PAYLOADS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
const SIGNED: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    Size,
    Format,
    Overflow,
    Identifier,
    Duplicate,
    Overlap,
    Digest,
    Signature,
    Architecture,
    Compression,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadView<'a> {
    pub name: &'a str,
    pub purpose: &'a str,
    pub architecture: &'a str,
    pub compression: &'a str,
    pub raw_len: usize,
    pub bytes: &'a [u8],
    pub digest: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageView<'a> {
    bytes: &'a [u8],
    table: usize,
    count: usize,
    unsigned_len: usize,
    pub id: &'a str,
    pub class: &'a str,
    pub version: u64,
    pub content_digest: [u8; 64],
    pub key_id: [u8; 64],
    pub signed: bool,
}

impl<'a> PackageView<'a> {
    pub fn payload_count(&self) -> usize {
        self.count
    }

    pub fn payload(&self, index: usize) -> Result<PayloadView<'a>, PackageError> {
        if index >= self.count {
            return Err(PackageError::Format);
        }
        entry(
            self.bytes,
            self.table + index * ENTRY_BYTES,
            self.unsigned_len,
        )
    }

    pub fn select(
        &self,
        purpose: &str,
        architecture: &str,
    ) -> Result<PayloadView<'a>, PackageError> {
        let mut selected = None;
        for index in 0..self.count {
            let payload = self.payload(index)?;
            if payload.purpose == purpose && payload.architecture == architecture {
                if selected.is_some() {
                    return Err(PackageError::Duplicate);
                }
                selected = Some(payload);
            }
        }
        selected.ok_or(PackageError::Architecture)
    }
}

pub fn parse(
    bytes: &[u8],
    require_signature: bool,
    boot_profile: bool,
) -> Result<PackageView<'_>, PackageError> {
    let maximum = if boot_profile {
        MAX_BOOT_PACKAGE_BYTES
    } else {
        MAX_PACKAGE_BYTES
    };
    if bytes.len() < HEADER_BYTES || bytes.len() > maximum || bytes[..16] != MAGIC {
        return Err(PackageError::Format);
    }
    if get_u16(bytes, 16)? != FORMAT_VERSION || get_u32(bytes, 20)? as usize != HEADER_BYTES {
        return Err(PackageError::Format);
    }
    let flags = get_u16(bytes, 18)?;
    if flags & !SIGNED != 0 {
        return Err(PackageError::Format);
    }
    let signed = flags & SIGNED != 0;
    if require_signature && !signed {
        return Err(PackageError::Signature);
    }
    let id_len = get_u32(bytes, 24)? as usize;
    let count = get_u32(bytes, 28)? as usize;
    let version = get_u64(bytes, 32)?;
    let table = usize_from(get_u64(bytes, 40)?)?;
    let payload_start = usize_from(get_u64(bytes, 48)?)?;
    let signature_offset = usize_from(get_u64(bytes, 56)?)?;
    let total = usize_from(get_u64(bytes, 64)?)?;
    if total != bytes.len()
        || id_len == 0
        || id_len > MAX_IDENTIFIER_BYTES
        || count == 0
        || count > MAX_PAYLOADS
        || version == 0
    {
        return Err(PackageError::Size);
    }
    if table
        != HEADER_BYTES
            .checked_add(id_len)
            .ok_or(PackageError::Overflow)?
        || payload_start
            != table
                .checked_add(
                    count
                        .checked_mul(ENTRY_BYTES)
                        .ok_or(PackageError::Overflow)?,
                )
                .ok_or(PackageError::Overflow)?
    {
        return Err(PackageError::Format);
    }
    let unsigned_len = if signed {
        signature_offset
    } else {
        bytes.len()
    };
    if unsigned_len < payload_start
        || (signed
            && bytes.len().checked_sub(unsigned_len)
                != Some(LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES))
        || (!signed && signature_offset != 0)
    {
        return Err(PackageError::Format);
    }
    let id =
        core::str::from_utf8(&bytes[HEADER_BYTES..table]).map_err(|_| PackageError::Identifier)?;
    let class = fixed_str(&bytes[72..104])?;
    if !identifier(id) || !token(class, 32) {
        return Err(PackageError::Identifier);
    }
    let mut expected_digest = [0_u8; 64];
    expected_digest.copy_from_slice(&bytes[104..168]);
    if content_digest(&bytes[..unsigned_len])? != expected_digest {
        return Err(PackageError::Digest);
    }
    let mut key_id = [0_u8; 64];
    key_id.copy_from_slice(&bytes[168..232]);
    if signed {
        let public = &bytes[unsigned_len..unsigned_len + LAMPORT_PUBLIC_KEY_BYTES];
        let signature = &bytes[unsigned_len + LAMPORT_PUBLIC_KEY_BYTES..];
        if Sha3_512::digest(public) != key_id
            || lamport_verify(public, &signature_statement(&expected_digest), signature).is_err()
        {
            return Err(PackageError::Signature);
        }
    } else if key_id != [0; 64] {
        return Err(PackageError::Format);
    }
    let mut previous_end = payload_start;
    for index in 0..count {
        let payload = entry(bytes, table + index * ENTRY_BYTES, unsigned_len)?;
        let offset = payload.bytes.as_ptr() as usize - bytes.as_ptr() as usize;
        if offset < previous_end {
            return Err(PackageError::Overlap);
        }
        previous_end = offset
            .checked_add(payload.bytes.len())
            .ok_or(PackageError::Overflow)?;
        for prior in 0..index {
            let other = entry(bytes, table + prior * ENTRY_BYTES, unsigned_len)?;
            if other.name == payload.name
                && other.purpose == payload.purpose
                && other.architecture == payload.architecture
            {
                return Err(PackageError::Duplicate);
            }
        }
    }
    if previous_end != unsigned_len {
        return Err(PackageError::Format);
    }
    Ok(PackageView {
        bytes,
        table,
        count,
        unsigned_len,
        id,
        class,
        version,
        content_digest: expected_digest,
        key_id,
        signed,
    })
}

impl PayloadView<'_> {
    pub fn decode(&self, output: &mut [u8]) -> Result<usize, PackageError> {
        if output.len() < self.raw_len {
            return Err(PackageError::Output);
        }
        let written = match self.compression {
            "none" => {
                if self.bytes.len() != self.raw_len {
                    return Err(PackageError::Compression);
                }
                output[..self.raw_len].copy_from_slice(self.bytes);
                self.raw_len
            }
            "zstd" => zstd_raw_decode(self.bytes, &mut output[..self.raw_len])?,
            _ => return Err(PackageError::Compression),
        };
        if written != self.raw_len || Sha3_512::digest(&output[..written]) != self.digest {
            return Err(PackageError::Digest);
        }
        Ok(written)
    }
}

fn entry(bytes: &[u8], entry: usize, unsigned_len: usize) -> Result<PayloadView<'_>, PackageError> {
    let end_entry = entry
        .checked_add(ENTRY_BYTES)
        .ok_or(PackageError::Overflow)?;
    if end_entry > bytes.len() {
        return Err(PackageError::Format);
    }
    let name = fixed_str(&bytes[entry..entry + 32])?;
    let purpose = fixed_str(&bytes[entry + 32..entry + 48])?;
    let architecture = fixed_str(&bytes[entry + 48..entry + 64])?;
    let compression = fixed_str(&bytes[entry + 64..entry + 80])?;
    if !token(name, 32)
        || !token(purpose, 16)
        || !token(architecture, 16)
        || !matches!(compression, "none" | "zstd")
    {
        return Err(PackageError::Identifier);
    }
    let offset = usize_from(get_u64(bytes, entry + 80)?)?;
    let stored_len = usize_from(get_u64(bytes, entry + 88)?)?;
    let raw_len = usize_from(get_u64(bytes, entry + 96)?)?;
    let end = offset
        .checked_add(stored_len)
        .ok_or(PackageError::Overflow)?;
    if offset < HEADER_BYTES
        || end > unsigned_len
        || stored_len == 0
        || raw_len == 0
        || raw_len > MAX_PAYLOAD_BYTES
    {
        return Err(PackageError::Overlap);
    }
    let mut digest = [0_u8; 64];
    digest.copy_from_slice(&bytes[entry + 104..entry + 168]);
    if bytes[entry + 168..entry + ENTRY_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(PackageError::Format);
    }
    Ok(PayloadView {
        name,
        purpose,
        architecture,
        compression,
        raw_len,
        bytes: &bytes[offset..end],
        digest,
    })
}

fn content_digest(bytes: &[u8]) -> Result<[u8; 64], PackageError> {
    if bytes.len() < HEADER_BYTES {
        return Err(PackageError::Format);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"MRML-PACKAGE-CONTENT-v1\0");
    hash.update(&bytes[..18]);
    hash.update(&[0, 0]);
    hash.update(&bytes[20..56]);
    hash.update(&[0; 8]);
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(&bytes[72..104]);
    hash.update(&[0; 128]);
    hash.update(&bytes[232..]);
    Ok(hash.finalize())
}
fn signature_statement(digest: &[u8; 64]) -> [u8; 90] {
    let mut value = [0_u8; 90];
    let prefix = b"MRML-PACKAGE-SIGNATURE-v1\0";
    value[..prefix.len()].copy_from_slice(prefix);
    value[prefix.len()..].copy_from_slice(digest);
    value
}
fn zstd_raw_decode(input: &[u8], output: &mut [u8]) -> Result<usize, PackageError> {
    if input.len() < 9 || input[..5] != [0x28, 0xb5, 0x2f, 0xfd, 0xa0] {
        return Err(PackageError::Compression);
    }
    let declared = u32::from_le_bytes(
        input[5..9]
            .try_into()
            .map_err(|_| PackageError::Compression)?,
    ) as usize;
    if declared != output.len() {
        return Err(PackageError::Compression);
    }
    let (mut source, mut written, mut last) = (9, 0_usize, false);
    while source < input.len() {
        if last || source + 3 > input.len() {
            return Err(PackageError::Compression);
        }
        let h = u32::from_le_bytes([input[source], input[source + 1], input[source + 2], 0]);
        source += 3;
        last = h & 1 != 0;
        if (h >> 1) & 3 != 0 {
            return Err(PackageError::Compression);
        }
        let size = (h >> 3) as usize;
        let end = source.checked_add(size).ok_or(PackageError::Overflow)?;
        let out = written.checked_add(size).ok_or(PackageError::Overflow)?;
        if end > input.len() || out > output.len() {
            return Err(PackageError::Compression);
        }
        output[written..out].copy_from_slice(&input[source..end]);
        source = end;
        written = out
    }
    if !last || written != declared {
        return Err(PackageError::Compression);
    }
    Ok(written)
}
fn identifier(v: &str) -> bool {
    v.len() <= MAX_IDENTIFIER_BYTES
        && v.starts_with("org.mrml.")
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}
fn token(v: &str, m: usize) -> bool {
    !v.is_empty()
        && v.len() <= m
        && v.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}
fn fixed_str(b: &[u8]) -> Result<&str, PackageError> {
    let e = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    if b[e..].iter().any(|x| *x != 0) {
        return Err(PackageError::Format);
    }
    core::str::from_utf8(&b[..e]).map_err(|_| PackageError::Identifier)
}
fn usize_from(v: u64) -> Result<usize, PackageError> {
    usize::try_from(v).map_err(|_| PackageError::Overflow)
}
fn get_u16(b: &[u8], o: usize) -> Result<u16, PackageError> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2)
            .ok_or(PackageError::Format)?
            .try_into()
            .map_err(|_| PackageError::Format)?,
    ))
}
fn get_u32(b: &[u8], o: usize) -> Result<u32, PackageError> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4)
            .ok_or(PackageError::Format)?
            .try_into()
            .map_err(|_| PackageError::Format)?,
    ))
}
fn get_u64(b: &[u8], o: usize) -> Result<u64, PackageError> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8)
            .ok_or(PackageError::Format)?
            .try_into()
            .map_err(|_| PackageError::Format)?,
    ))
}
