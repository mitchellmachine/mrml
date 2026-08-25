use crate::package_lamport::{
    LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
    lamport_public_key, lamport_sign, lamport_verify,
};
use crate::package_sha3::Sha3_512;

pub const MAGIC: [u8; 16] = *b"MRML-PACKAGE-v1\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 256;
pub const ENTRY_BYTES: usize = 192;
pub const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_PAYLOADS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
const SIGNED: u16 = 1;
const ZSTD: &str = "zstd";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payload<'a> {
    pub name: &'a str,
    pub purpose: &'a str,
    pub architecture: &'a str,
    pub compression: &'a str,
    pub raw_len: usize,
    pub bytes: &'a [u8],
    pub digest: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Package<'a> {
    pub id: &'a str,
    pub class: &'a str,
    pub version: u64,
    pub content_digest: [u8; 64],
    pub key_id: [u8; 64],
    pub signed: bool,
    pub payloads: Vec<Payload<'a>>,
}

pub struct BuildPayload<'a> {
    pub name: &'a str,
    pub purpose: &'a str,
    pub architecture: &'a str,
    pub compress: bool,
    pub bytes: &'a [u8],
}

pub fn build(
    id: &str,
    class: &str,
    version: u64,
    payloads: &[BuildPayload<'_>],
    private_key: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if !identifier(id)
        || !token(class, 32)
        || version == 0
        || payloads.is_empty()
        || payloads.len() > MAX_PAYLOADS
    {
        return Err(Error::Identifier);
    }
    if private_key.is_some_and(|key| key.len() != LAMPORT_PRIVATE_KEY_BYTES) {
        return Err(Error::Signature);
    }
    let table_offset = HEADER_BYTES.checked_add(id.len()).ok_or(Error::Overflow)?;
    let payload_offset = table_offset
        .checked_add(
            payloads
                .len()
                .checked_mul(ENTRY_BYTES)
                .ok_or(Error::Overflow)?,
        )
        .ok_or(Error::Overflow)?;
    let mut stored = Vec::with_capacity(payloads.len());
    let mut payload_bytes = 0_usize;
    for payload in payloads {
        if !token(payload.name, 32)
            || !token(payload.purpose, 16)
            || !token(payload.architecture, 16)
            || payload.bytes.is_empty()
            || payload.bytes.len() > MAX_PAYLOAD_BYTES
        {
            return Err(Error::Identifier);
        }
        if stored.iter().any(
            |(name, purpose, arch, _, _, _): &(&str, &str, &str, Vec<u8>, usize, [u8; 64])| {
                *name == payload.name
                    && *purpose == payload.purpose
                    && *arch == payload.architecture
            },
        ) {
            return Err(Error::Duplicate);
        }
        let encoded = if payload.compress {
            zstd_raw_frame(payload.bytes)?
        } else {
            payload.bytes.to_vec()
        };
        payload_bytes = payload_bytes
            .checked_add(encoded.len())
            .ok_or(Error::Overflow)?;
        stored.push((
            payload.name,
            payload.purpose,
            payload.architecture,
            encoded,
            payload.bytes.len(),
            Sha3_512::digest(payload.bytes),
        ));
    }
    let unsigned_len = payload_offset
        .checked_add(payload_bytes)
        .ok_or(Error::Overflow)?;
    let signature_bytes = if private_key.is_some() {
        LAMPORT_PUBLIC_KEY_BYTES
            .checked_add(LAMPORT_SIGNATURE_BYTES)
            .ok_or(Error::Overflow)?
    } else {
        0
    };
    let total_len = unsigned_len
        .checked_add(signature_bytes)
        .ok_or(Error::Overflow)?;
    if total_len > MAX_PACKAGE_BYTES {
        return Err(Error::Size);
    }
    let mut output = vec![0_u8; total_len];
    output[..16].copy_from_slice(&MAGIC);
    put_u16(&mut output, 16, FORMAT_VERSION)?;
    put_u16(
        &mut output,
        18,
        if private_key.is_some() { SIGNED } else { 0 },
    )?;
    put_u32(&mut output, 20, HEADER_BYTES as u32)?;
    put_u32(&mut output, 24, id.len() as u32)?;
    put_u32(&mut output, 28, payloads.len() as u32)?;
    put_u64(&mut output, 32, version)?;
    put_u64(&mut output, 40, table_offset as u64)?;
    put_u64(&mut output, 48, payload_offset as u64)?;
    put_u64(
        &mut output,
        56,
        if private_key.is_some() {
            unsigned_len as u64
        } else {
            0
        },
    )?;
    put_u64(&mut output, 64, total_len as u64)?;
    fixed(&mut output[72..104], class)?;
    output[HEADER_BYTES..table_offset].copy_from_slice(id.as_bytes());
    let mut cursor = payload_offset;
    for (index, (name, purpose, architecture, bytes, raw_len, digest)) in stored.iter().enumerate()
    {
        let entry = table_offset + index * ENTRY_BYTES;
        fixed(&mut output[entry..entry + 32], name)?;
        fixed(&mut output[entry + 32..entry + 48], purpose)?;
        fixed(&mut output[entry + 48..entry + 64], architecture)?;
        fixed(
            &mut output[entry + 64..entry + 80],
            if payloads[index].compress {
                ZSTD
            } else {
                "none"
            },
        )?;
        put_u64(&mut output, entry + 80, cursor as u64)?;
        put_u64(&mut output, entry + 88, bytes.len() as u64)?;
        put_u64(&mut output, entry + 96, *raw_len as u64)?;
        output[entry + 104..entry + 168].copy_from_slice(digest);
        output[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
    }
    let content_digest = content_digest(&output[..unsigned_len])?;
    output[104..168].copy_from_slice(&content_digest);
    if let Some(private) = private_key {
        let mut public = vec![0_u8; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = vec![0_u8; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(private, &mut public).map_err(|_| Error::Signature)?;
        let statement = signature_statement(&content_digest);
        lamport_sign(private, &statement, &mut signature).map_err(|_| Error::Signature)?;
        let key_id = Sha3_512::digest(&public);
        output[168..232].copy_from_slice(&key_id);
        output[unsigned_len..unsigned_len + public.len()].copy_from_slice(&public);
        output[unsigned_len + public.len()..].copy_from_slice(&signature);
    }
    Ok(output)
}

pub fn parse(bytes: &[u8], require_signature: bool) -> Result<Package<'_>, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_PACKAGE_BYTES || bytes[..16] != MAGIC {
        return Err(Error::Format);
    }
    if get_u16(bytes, 16)? != FORMAT_VERSION || get_u32(bytes, 20)? as usize != HEADER_BYTES {
        return Err(Error::Format);
    }
    let flags = get_u16(bytes, 18)?;
    if flags & !SIGNED != 0 {
        return Err(Error::Format);
    }
    let signed = flags & SIGNED != 0;
    if require_signature && !signed {
        return Err(Error::Signature);
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
        return Err(Error::Size);
    }
    if table != HEADER_BYTES.checked_add(id_len).ok_or(Error::Overflow)?
        || payload_start
            != table
                .checked_add(count.checked_mul(ENTRY_BYTES).ok_or(Error::Overflow)?)
                .ok_or(Error::Overflow)?
    {
        return Err(Error::Format);
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
        return Err(Error::Format);
    }
    let id = core::str::from_utf8(&bytes[HEADER_BYTES..table]).map_err(|_| Error::Identifier)?;
    let class = fixed_str(&bytes[72..104])?;
    if !identifier(id) || !token(class, 32) {
        return Err(Error::Identifier);
    }
    let mut expected_digest = [0_u8; 64];
    expected_digest.copy_from_slice(&bytes[104..168]);
    if content_digest(&bytes[..unsigned_len])? != expected_digest {
        return Err(Error::Digest);
    }
    let mut key_id = [0_u8; 64];
    key_id.copy_from_slice(&bytes[168..232]);
    if signed {
        let public = &bytes[unsigned_len..unsigned_len + LAMPORT_PUBLIC_KEY_BYTES];
        let signature = &bytes[unsigned_len + LAMPORT_PUBLIC_KEY_BYTES..];
        if Sha3_512::digest(public) != key_id
            || lamport_verify(public, &signature_statement(&expected_digest), signature).is_err()
        {
            return Err(Error::Signature);
        }
    } else if key_id != [0; 64] {
        return Err(Error::Format);
    }
    let mut payloads = Vec::with_capacity(count);
    let mut previous_end = payload_start;
    for index in 0..count {
        let entry = table + index * ENTRY_BYTES;
        let name = fixed_str(&bytes[entry..entry + 32])?;
        let purpose = fixed_str(&bytes[entry + 32..entry + 48])?;
        let architecture = fixed_str(&bytes[entry + 48..entry + 64])?;
        let compression = fixed_str(&bytes[entry + 64..entry + 80])?;
        let offset = usize_from(get_u64(bytes, entry + 80)?)?;
        let stored_len = usize_from(get_u64(bytes, entry + 88)?)?;
        let raw_len = usize_from(get_u64(bytes, entry + 96)?)?;
        let end = offset.checked_add(stored_len).ok_or(Error::Overflow)?;
        if offset < previous_end
            || end > unsigned_len
            || stored_len == 0
            || raw_len == 0
            || raw_len > MAX_PAYLOAD_BYTES
        {
            return Err(Error::Overlap);
        }
        let mut digest = [0_u8; 64];
        digest.copy_from_slice(&bytes[entry + 104..entry + 168]);
        if payloads.iter().any(|item: &Payload<'_>| {
            item.name == name && item.purpose == purpose && item.architecture == architecture
        }) {
            return Err(Error::Duplicate);
        }
        payloads.push(Payload {
            name,
            purpose,
            architecture,
            compression,
            raw_len,
            bytes: &bytes[offset..end],
            digest,
        });
        previous_end = end;
    }
    if previous_end != unsigned_len {
        return Err(Error::Format);
    }
    Ok(Package {
        id,
        class,
        version,
        content_digest: expected_digest,
        key_id,
        signed,
        payloads,
    })
}

impl Payload<'_> {
    pub fn decode(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.raw_len {
            return Err(Error::Output);
        }
        let written = match self.compression {
            "none" => {
                if self.bytes.len() != self.raw_len {
                    return Err(Error::Compression);
                }
                output[..self.raw_len].copy_from_slice(self.bytes);
                self.raw_len
            }
            ZSTD => zstd_raw_decode(self.bytes, &mut output[..self.raw_len])?,
            _ => return Err(Error::Compression),
        };
        if written != self.raw_len || Sha3_512::digest(&output[..written]) != self.digest {
            return Err(Error::Digest);
        }
        Ok(written)
    }
}

pub fn select<'a>(
    package: &'a Package<'a>,
    purpose: &str,
    architecture: &str,
) -> Result<&'a Payload<'a>, Error> {
    let mut matches = package
        .payloads
        .iter()
        .filter(|payload| payload.purpose == purpose && payload.architecture == architecture);
    let result = matches.next().ok_or(Error::Architecture)?;
    if matches.next().is_some() {
        return Err(Error::Duplicate);
    }
    Ok(result)
}

fn content_digest(bytes: &[u8]) -> Result<[u8; 64], Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::Format);
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

fn signature_statement(digest: &[u8; 64]) -> Vec<u8> {
    let mut value = b"MRML-PACKAGE-SIGNATURE-v1\0".to_vec();
    value.extend_from_slice(digest);
    value
}

fn zstd_raw_frame(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Size);
    }
    let mut out = Vec::with_capacity(input.len() + 32);
    out.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0xa0]);
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    let mut offset = 0;
    while offset < input.len() {
        let size = core::cmp::min(128 * 1024, input.len() - offset);
        let last = usize::from(offset + size == input.len());
        let header = (size << 3) | last;
        out.extend_from_slice(&(header as u32).to_le_bytes()[..3]);
        out.extend_from_slice(&input[offset..offset + size]);
        offset += size;
    }
    Ok(out)
}

fn zstd_raw_decode(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if input.len() < 9 || input[..5] != [0x28, 0xb5, 0x2f, 0xfd, 0xa0] {
        return Err(Error::Compression);
    }
    let declared =
        u32::from_le_bytes(input[5..9].try_into().map_err(|_| Error::Compression)?) as usize;
    if declared != output.len() {
        return Err(Error::Compression);
    }
    let mut source = 9;
    let mut written = 0_usize;
    let mut saw_last = false;
    while source < input.len() {
        if saw_last || source + 3 > input.len() {
            return Err(Error::Compression);
        }
        let header = u32::from_le_bytes([input[source], input[source + 1], input[source + 2], 0]);
        source += 3;
        saw_last = header & 1 != 0;
        if (header >> 1) & 3 != 0 {
            return Err(Error::Compression);
        }
        let size = (header >> 3) as usize;
        let end = source.checked_add(size).ok_or(Error::Overflow)?;
        let output_end = written.checked_add(size).ok_or(Error::Overflow)?;
        if end > input.len() || output_end > output.len() {
            return Err(Error::Compression);
        }
        output[written..output_end].copy_from_slice(&input[source..end]);
        source = end;
        written = output_end;
    }
    if !saw_last || written != declared {
        return Err(Error::Compression);
    }
    Ok(written)
}

fn identifier(value: &str) -> bool {
    value.len() <= MAX_IDENTIFIER_BYTES
        && value.starts_with("org.mrml.")
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}
fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}
fn fixed(output: &mut [u8], value: &str) -> Result<(), Error> {
    if !token(value, output.len()) {
        return Err(Error::Identifier);
    }
    output[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}
fn fixed_str(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(Error::Format);
    }
    core::str::from_utf8(&bytes[..end]).map_err(|_| Error::Identifier)
}
fn usize_from(value: u64) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::Overflow)
}
fn get_u16(b: &[u8], o: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn get_u32(b: &[u8], o: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn get_u64(b: &[u8], o: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn put_u16(b: &mut [u8], o: usize, v: u16) -> Result<(), Error> {
    b.get_mut(o..o + 2)
        .ok_or(Error::Format)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn put_u32(b: &mut [u8], o: usize, v: u32) -> Result<(), Error> {
    b.get_mut(o..o + 4)
        .ok_or(Error::Format)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn put_u64(b: &mut [u8], o: usize, v: u64) -> Result<(), Error> {
    b.get_mut(o..o + 8)
        .ok_or(Error::Format)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_key() -> Vec<u8> {
        (0..LAMPORT_PRIVATE_KEY_BYTES)
            .map(|i| (i as u64 * 131 + 17) as u8)
            .collect()
    }

    #[test]
    fn canonical_signed_round_trip_and_architecture_selection() {
        let key = private_key();
        let bytes = build(
            "org.mrml.system.kernel",
            "kernel",
            7,
            &[BuildPayload {
                name: "kernel",
                purpose: "kernel",
                architecture: "x86_64",
                compress: true,
                bytes: b"kernel payload",
            }],
            Some(&key),
        )
        .unwrap();
        let package = parse(&bytes, true).unwrap();
        let boot = crate::boot_package_core::parse(&bytes, true, true).unwrap();
        assert_eq!(boot.id, package.id);
        assert_eq!(boot.class, package.class);
        assert_eq!(boot.version, package.version);
        assert_eq!(boot.content_digest, package.content_digest);
        assert_eq!(boot.payload_count(), package.payloads.len());
        assert!(package.signed);
        let payload = select(&package, "kernel", "x86_64").unwrap();
        let mut decoded = [0_u8; 14];
        assert_eq!(payload.decode(&mut decoded), Ok(14));
        assert_eq!(&decoded, b"kernel payload");
        let boot_payload = boot.select("kernel", "x86_64").unwrap();
        let mut boot_decoded = [0_u8; 14];
        assert_eq!(boot_payload.decode(&mut boot_decoded), Ok(14));
        assert_eq!(boot_decoded, decoded);
        assert_eq!(
            build(
                "org.mrml.system.kernel",
                "kernel",
                7,
                &[BuildPayload {
                    name: "kernel",
                    purpose: "kernel",
                    architecture: "x86_64",
                    compress: true,
                    bytes: b"kernel payload"
                }],
                Some(&key)
            )
            .unwrap(),
            bytes
        );
        let unsigned = build(
            "org.mrml.system.kernel",
            "kernel",
            7,
            &[BuildPayload {
                name: "kernel",
                purpose: "kernel",
                architecture: "x86_64",
                compress: true,
                bytes: b"kernel payload",
            }],
            None,
        )
        .unwrap();
        assert_eq!(
            parse(&unsigned, false).unwrap().content_digest,
            package.content_digest
        );
    }

    #[test]
    fn rejects_unsigned_tampered_truncated_and_wrong_architecture() {
        let bytes = build(
            "org.mrml.system.kernel",
            "kernel",
            1,
            &[BuildPayload {
                name: "kernel",
                purpose: "kernel",
                architecture: "x86_64",
                compress: false,
                bytes: b"abc",
            }],
            None,
        )
        .unwrap();
        assert_eq!(parse(&bytes, true), Err(Error::Signature));
        let package = parse(&bytes, false).unwrap();
        assert_eq!(
            select(&package, "kernel", "aarch64"),
            Err(Error::Architecture)
        );
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(parse(&tampered, false), Err(Error::Digest));
        assert!(parse(&bytes[..bytes.len() - 1], false).is_err());
    }

    #[test]
    fn malformed_offsets_unknown_flags_and_zstd_truncation_fail_closed() {
        let mut bytes = build(
            "org.mrml.system.kernel",
            "kernel",
            1,
            &[BuildPayload {
                name: "kernel",
                purpose: "kernel",
                architecture: "x86_64",
                compress: true,
                bytes: &[7; 300_000],
            }],
            None,
        )
        .unwrap();
        bytes[18] = 0x80;
        assert_eq!(parse(&bytes, false), Err(Error::Format));
        let mut output = [0_u8; 3];
        assert!(
            zstd_raw_decode(&[0x28, 0xb5, 0x2f, 0xfd, 0xa0, 3, 0, 0, 0, 1], &mut output).is_err()
        );
    }
}
