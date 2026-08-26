use crate::boot_release_core::{
    BootPackageRole, MAX_BOOT_RELEASE_BYTES, RELEASE_FORMAT_VERSION, RELEASE_HEADER_BYTES,
    RELEASE_MAGIC, RELEASE_PACKAGE_COUNT, RELEASE_RECORD_BYTES, parse_release, release_digest,
    release_statement,
};
use crate::package_lamport::{
    LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
    lamport_public_key, lamport_sign, lamport_verify,
};
use crate::package_sha3::Sha3_512;
use crate::system_release::{
    MAX_SYSTEM_RELEASE_BYTES, encode_system_release, encode_system_release_with_runtime_inventory,
};

pub const MAGIC: [u8; 16] = *b"MRML-PACKAGE-v1\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 256;
pub const ENTRY_BYTES: usize = 192;
pub const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_PAYLOADS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
pub const PACKAGE_EXTENSION: &str = "mrp";
pub const RELEASE_EXTENSION: &str = "mrs";
pub const SYSTEM_IMAGE_EXTENSION: &str = "mrz";
pub const INTERFACE_EXTENSION: &str = "mri";
pub const DETACHED_SIGNATURE_EXTENSION: &str = "mrsig";
const SIGNED: u16 = 1;
const ZSTD: &str = "zstd";

pub fn build_system_release(
    generation_bytes: &[u8],
    catalog_bytes: &[u8],
    private: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; MAX_SYSTEM_RELEASE_BYTES];
    let total = encode_system_release(generation_bytes, catalog_bytes, private, &mut output)
        .map_err(|_| Error::Format)?;
    output.truncate(total);
    Ok(output)
}

pub fn build_system_release_with_runtime_inventory(
    generation_bytes: &[u8],
    catalog_bytes: &[u8],
    runtime_inventory_bytes: &[u8],
    private: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; MAX_SYSTEM_RELEASE_BYTES];
    let total = encode_system_release_with_runtime_inventory(
        generation_bytes,
        catalog_bytes,
        runtime_inventory_bytes,
        private,
        &mut output,
    )
    .map_err(|_| Error::Format)?;
    output.truncate(total);
    Ok(output)
}

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

pub fn default_package_filename(id: &str, version: u64) -> Result<String, Error> {
    if !identifier(id) || version == 0 {
        return Err(Error::Identifier);
    }
    Ok(format!("{id}-{version}.{PACKAGE_EXTENSION}"))
}

pub fn default_release_filename(version: u64) -> Result<String, Error> {
    if version == 0 {
        return Err(Error::Identifier);
    }
    Ok(format!("mrml-system-{version}.{RELEASE_EXTENSION}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSizeBreakdown {
    pub total_bytes: usize,
    pub raw_payload_bytes: usize,
    pub stored_payload_bytes: usize,
    pub format_metadata_bytes: usize,
    pub signature_bytes: usize,
}

pub fn size_breakdown(
    package: &Package<'_>,
    total_bytes: usize,
) -> Result<PackageSizeBreakdown, Error> {
    let raw_payload_bytes = package.payloads.iter().try_fold(0usize, |total, payload| {
        total.checked_add(payload.raw_len).ok_or(Error::Overflow)
    })?;
    let stored_payload_bytes = package.payloads.iter().try_fold(0usize, |total, payload| {
        total
            .checked_add(payload.bytes.len())
            .ok_or(Error::Overflow)
    })?;
    let signature_bytes = if package.signed {
        LAMPORT_PUBLIC_KEY_BYTES
            .checked_add(LAMPORT_SIGNATURE_BYTES)
            .ok_or(Error::Overflow)?
    } else {
        0
    };
    let accounted = stored_payload_bytes
        .checked_add(signature_bytes)
        .ok_or(Error::Overflow)?;
    let format_metadata_bytes = total_bytes.checked_sub(accounted).ok_or(Error::Size)?;
    Ok(PackageSizeBreakdown {
        total_bytes,
        raw_payload_bytes,
        stored_payload_bytes,
        format_metadata_bytes,
        signature_bytes,
    })
}

pub fn build_release(
    version: u64,
    bootloader: &[u8],
    kernel: &[u8],
    configuration: &[u8],
    private: &[u8],
) -> Result<Vec<u8>, Error> {
    if version == 0 || private.len() != LAMPORT_PRIVATE_KEY_BYTES {
        return Err(Error::Signature);
    }
    let packages = [
        (
            BootPackageRole::Bootloader,
            "org.mrml.library.uefi",
            "bootloader",
            "uefi-loader",
            bootloader,
        ),
        (
            BootPackageRole::Kernel,
            "org.mrml.system.kernel",
            "kernel",
            "kernel",
            kernel,
        ),
        (
            BootPackageRole::Configuration,
            "org.mrml.service.config",
            "configuration",
            "configuration",
            configuration,
        ),
    ];
    let mut records = [(BootPackageRole::Bootloader, 0, [0; 64]); RELEASE_PACKAGE_COUNT];
    for (index, (role, id, class, purpose, bytes)) in packages.into_iter().enumerate() {
        let package = parse(bytes, true)?;
        if package.id != id
            || package.class != class
            || package
                .payloads
                .iter()
                .filter(|payload| payload.purpose == purpose && payload.architecture == "x86_64")
                .count()
                != 1
        {
            return Err(Error::Architecture);
        }
        records[index] = (role, package.version, Sha3_512::digest(bytes));
    }
    build_release_records(version, records, private)
}

fn build_release_records(
    version: u64,
    records: [(BootPackageRole, u64, [u8; 64]); RELEASE_PACKAGE_COUNT],
    private: &[u8],
) -> Result<Vec<u8>, Error> {
    if version == 0 || private.len() != LAMPORT_PRIVATE_KEY_BYTES {
        return Err(Error::Signature);
    }
    let mut output = vec![0; MAX_BOOT_RELEASE_BYTES];
    output[..16].copy_from_slice(&RELEASE_MAGIC);
    put_u16(&mut output, 16, RELEASE_FORMAT_VERSION)?;
    put_u16(&mut output, 18, 1)?;
    put_u32(&mut output, 20, RELEASE_HEADER_BYTES as u32)?;
    put_u64(&mut output, 24, version)?;
    put_u64(&mut output, 32, MAX_BOOT_RELEASE_BYTES as u64)?;
    put_u32(&mut output, 40, RELEASE_PACKAGE_COUNT as u32)?;
    let mut public = vec![0; LAMPORT_PUBLIC_KEY_BYTES];
    lamport_public_key(private, &mut public).map_err(|_| Error::Signature)?;
    output[112..176].copy_from_slice(&Sha3_512::digest(&public));
    for (index, (role, package_version, digest)) in records.into_iter().enumerate() {
        let offset = 176 + index * RELEASE_RECORD_BYTES;
        output[offset] = role as u8;
        output[offset + 1] = 1;
        put_u64(&mut output, offset + 8, package_version)?;
        output[offset + 16..offset + 80].copy_from_slice(&digest);
    }
    let digest = release_digest(&output[..RELEASE_HEADER_BYTES]);
    output[48..112].copy_from_slice(&digest);
    let mut signature = vec![0; LAMPORT_SIGNATURE_BYTES];
    lamport_sign(private, &release_statement(&digest), &mut signature)
        .map_err(|_| Error::Signature)?;
    output[RELEASE_HEADER_BYTES..RELEASE_HEADER_BYTES + public.len()].copy_from_slice(&public);
    output[RELEASE_HEADER_BYTES + public.len()..].copy_from_slice(&signature);
    parse_release(&output, true).map_err(|_| Error::Signature)?;
    Ok(output)
}

pub fn build_adversarial_boot_fixture(
    case: &str,
    bootloader: &[u8],
    configuration: &[u8],
    kernel_payload: &[u8],
    package_private: &[u8],
    release_private: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (class, architecture, compress) = match case {
        "bad-signature"
        | "malformed-offset"
        | "truncated-compressed-payload"
        | "wrong-release-digest"
        | "incompatible-generation"
        | "missing-package" => ("kernel", "x86_64", case == "truncated-compressed-payload"),
        "unsupported-architecture" => ("kernel", "aarch64", false),
        "wrong-class" => ("vmm", "x86_64", false),
        _ => return Err(Error::Identifier),
    };
    let mut kernel = build(
        "org.mrml.system.kernel",
        class,
        1,
        &[BuildPayload {
            name: "kernel",
            purpose: "kernel",
            architecture,
            compress,
            bytes: kernel_payload,
        }],
        None,
    )?;
    match case {
        "malformed-offset" => {
            let table = HEADER_BYTES + "org.mrml.system.kernel".len();
            put_u64(&mut kernel, table + 80, 1)?;
        }
        "truncated-compressed-payload" => {
            kernel.pop().ok_or(Error::Size)?;
            let table = HEADER_BYTES + "org.mrml.system.kernel".len();
            let stored = get_u64(&kernel, table + 88)?;
            put_u64(
                &mut kernel,
                table + 88,
                stored.checked_sub(1).ok_or(Error::Size)?,
            )?;
        }
        _ => {}
    }
    sign_package_fixture(&mut kernel, package_private)?;
    if case == "bad-signature" {
        let last = kernel.last_mut().ok_or(Error::Size)?;
        *last ^= 1;
    }

    let boot = parse(bootloader, true)?;
    let config = parse(configuration, true)?;
    let mut kernel_digest = Sha3_512::digest(&kernel);
    if case == "wrong-release-digest" {
        kernel_digest[0] ^= 1;
    }
    let kernel_version = if case == "incompatible-generation" {
        2
    } else {
        1
    };
    let records = [
        (
            BootPackageRole::Bootloader,
            boot.version,
            Sha3_512::digest(bootloader),
        ),
        (BootPackageRole::Kernel, kernel_version, kernel_digest),
        (
            BootPackageRole::Configuration,
            config.version,
            Sha3_512::digest(configuration),
        ),
    ];
    let release = build_release_records(1, records, release_private)?;
    Ok((kernel, release))
}

fn sign_package_fixture(output: &mut Vec<u8>, private: &[u8]) -> Result<(), Error> {
    if private.len() != LAMPORT_PRIVATE_KEY_BYTES || output.len() < HEADER_BYTES {
        return Err(Error::Signature);
    }
    let unsigned_len = output.len();
    let total = unsigned_len
        .checked_add(LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES)
        .ok_or(Error::Overflow)?;
    put_u16(output, 18, SIGNED)?;
    put_u64(output, 56, unsigned_len as u64)?;
    put_u64(output, 64, total as u64)?;
    let digest = content_digest(output)?;
    output[104..168].copy_from_slice(&digest);
    let mut public = vec![0; LAMPORT_PUBLIC_KEY_BYTES];
    let mut signature = vec![0; LAMPORT_SIGNATURE_BYTES];
    lamport_public_key(private, &mut public).map_err(|_| Error::Signature)?;
    lamport_sign(private, &signature_statement(&digest), &mut signature)
        .map_err(|_| Error::Signature)?;
    output[168..232].copy_from_slice(&Sha3_512::digest(&public));
    output.extend_from_slice(&public);
    output.extend_from_slice(&signature);
    Ok(())
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
    use crate::{
        ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
        RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation,
    };
    use std::fs;

    fn private_key() -> Vec<u8> {
        (0..LAMPORT_PRIVATE_KEY_BYTES)
            .map(|i| (i as u64 * 131 + 17) as u8)
            .collect()
    }

    #[test]
    fn canonical_names_and_filesystem_suffixes_are_non_authoritative() {
        assert_eq!(
            default_package_filename("org.mrml.zstd", 15).unwrap(),
            "org.mrml.zstd-15.mrp"
        );
        assert_eq!(
            default_release_filename(105).unwrap(),
            "mrml-system-105.mrs"
        );
        assert_eq!(default_package_filename("bad", 1), Err(Error::Identifier));

        let encoded = build(
            "org.mrml.zstd",
            "library",
            15,
            &[BuildPayload {
                name: "zstd",
                purpose: "provider",
                architecture: "x86_64",
                compress: false,
                bytes: b"valid-package-content",
            }],
            None,
        )
        .unwrap();
        let directory = std::env::temp_dir().join(format!(
            "mrml-extension-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&directory).unwrap();
        let canonical = directory.join("org.mrml.zstd-15.mrp");
        let renamed = directory.join("foo.bin");
        let deceptive = directory.join("trusted-kernel.mrp");
        fs::write(&canonical, &encoded).unwrap();
        fs::rename(&canonical, &renamed).unwrap();
        let renamed_bytes = fs::read(&renamed).unwrap();
        let parsed = parse(&renamed_bytes, false).unwrap();
        assert_eq!((parsed.id, parsed.version), ("org.mrml.zstd", 15));
        fs::write(&deceptive, b"not an mrml package").unwrap();
        assert_eq!(
            parse(&fs::read(&deceptive).unwrap(), false),
            Err(Error::Format)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    fn release_package(id: &str, class: &str, purpose: &str, version: u64) -> Vec<u8> {
        build(
            id,
            class,
            version,
            &[BuildPayload {
                name: purpose,
                purpose,
                architecture: "x86_64",
                compress: true,
                bytes: purpose.as_bytes(),
            }],
            Some(&private_key()),
        )
        .unwrap()
    }

    fn private_key_seed(seed: u8) -> Vec<u8> {
        (0..LAMPORT_PRIVATE_KEY_BYTES)
            .map(|index| (index as u64 * 193 + seed as u64) as u8)
            .collect()
    }

    #[test]
    fn general_system_release_signs_exact_generation_and_catalog_bytes() {
        let records = [SystemGenerationDigestRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &[0x2f; 64],
        }];
        let mut generation = [0; 128];
        let generation_length = encode_system_generation(7, &records, &mut generation).unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
        )
        .unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(7, &[requirement], &[provider], &mut catalog).unwrap();
        let release = build_system_release(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &private_key(),
        )
        .unwrap();
        let parsed = crate::parse_system_release(&release).unwrap();
        assert_eq!(parsed.generation().generation(), 7);
        assert_eq!(parsed.interface_catalog().generation(), 7);
        assert!(parsed.runtime_inventory().is_none());

        let mut tampered = release;
        tampered[crate::SYSTEM_RELEASE_HEADER_BYTES + generation_length + catalog_length - 1] ^= 1;
        assert!(crate::parse_system_release(&tampered).is_err());

        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &[0x2f; 64],
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length = encode_runtime_inventory(7, &[runtime_record], &mut runtime).unwrap();
        let release = build_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private_key(),
        )
        .unwrap();
        let parsed = crate::parse_system_release(&release).unwrap();
        assert_eq!(
            parsed.runtime_inventory().unwrap().generation(),
            parsed.generation().generation()
        );
        assert_eq!(parsed.runtime_inventory().unwrap().package_count(), 1);

        let mut tampered = release;
        let runtime_offset =
            crate::SYSTEM_RELEASE_RUNTIME_HEADER_BYTES + generation_length + catalog_length;
        tampered[runtime_offset + runtime_length - 1] ^= 1;
        assert!(crate::parse_system_release(&tampered).is_err());

        let wrong_length = encode_runtime_inventory(8, &[runtime_record], &mut runtime).unwrap();
        assert!(
            build_system_release_with_runtime_inventory(
                &generation[..generation_length],
                &catalog[..catalog_length],
                &runtime[..wrong_length],
                &private_key(),
            )
            .is_err()
        );
    }

    #[test]
    fn adversarial_boot_fixtures_reach_distinct_validation_boundaries() {
        let bootloader = release_package("org.mrml.library.uefi", "bootloader", "uefi-loader", 1);
        let configuration = release_package(
            "org.mrml.service.config",
            "configuration",
            "configuration",
            1,
        );
        for (index, case) in [
            "bad-signature",
            "malformed-offset",
            "truncated-compressed-payload",
            "wrong-release-digest",
            "incompatible-generation",
            "missing-package",
            "unsupported-architecture",
            "wrong-class",
        ]
        .into_iter()
        .enumerate()
        {
            let (kernel, release) = build_adversarial_boot_fixture(
                case,
                &bootloader,
                &configuration,
                b"signed kernel payload",
                &private_key_seed(index as u8 + 1),
                &private_key_seed(index as u8 + 65),
            )
            .unwrap();
            let release = parse_release(&release, true).unwrap();
            match case {
                "bad-signature" | "malformed-offset" => assert!(parse(&kernel, true).is_err()),
                "truncated-compressed-payload" => {
                    let package = parse(&kernel, true).unwrap();
                    let payload = select(&package, "kernel", "x86_64").unwrap();
                    let mut output = vec![0; payload.raw_len];
                    assert_eq!(payload.decode(&mut output), Err(Error::Compression));
                }
                "wrong-release-digest" => assert_ne!(
                    release.package(BootPackageRole::Kernel).package_digest,
                    Sha3_512::digest(&kernel)
                ),
                "incompatible-generation" => {
                    assert_eq!(release.package(BootPackageRole::Kernel).version, 2)
                }
                "unsupported-architecture" => {
                    let package = parse(&kernel, true).unwrap();
                    assert_eq!(
                        select(&package, "kernel", "x86_64"),
                        Err(Error::Architecture)
                    );
                }
                "wrong-class" => assert_eq!(parse(&kernel, true).unwrap().class, "vmm"),
                "missing-package" => assert!(parse(&kernel, true).is_ok()),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn bounded_mutation_corpus_never_bypasses_signed_parse_or_decode_bounds() {
        let private = private_key_seed(0x5a);
        let canonical = build(
            "org.mrml.system.kernel",
            "kernel",
            9,
            &[
                BuildPayload {
                    name: "kernel",
                    purpose: "kernel",
                    architecture: "x86_64",
                    compress: true,
                    bytes: &[0x4d; 257],
                },
                BuildPayload {
                    name: "configuration",
                    purpose: "configuration",
                    architecture: "x86_64",
                    compress: false,
                    bytes: &[0x72; 31],
                },
            ],
            Some(&private),
        )
        .unwrap();

        for truncated in (0..canonical.len()).step_by(127) {
            assert!(parse(&canonical[..truncated], true).is_err());
        }

        let mut state = 0x6d72_6d6c_u64;
        for _ in 0..512 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let offset = (state as usize) % canonical.len();
            let mut mutated = canonical.clone();
            mutated[offset] ^= 1 << ((state >> 32) & 7);
            let host = parse(&mutated, true);
            let boot = crate::boot_package_core::parse(&mutated, true, true);
            assert_eq!(host.is_ok(), boot.is_ok());
            if let (Ok(package), Ok(boot)) = (host, boot) {
                assert_eq!(package.id, boot.id);
                assert_eq!(package.class, boot.class);
                assert_eq!(package.version, boot.version);
                assert_eq!(package.content_digest, boot.content_digest);
                assert_eq!(package.payloads.len(), boot.payload_count());
                for payload in package.payloads {
                    let mut decoded = vec![0; payload.raw_len];
                    let result = payload.decode(&mut decoded);
                    assert!(result.is_ok() || result == Err(Error::Compression));
                    let boot_payload = boot
                        .select(payload.purpose, payload.architecture)
                        .expect("boot parser must expose the same accepted payload");
                    let mut boot_decoded = vec![0; boot_payload.raw_len];
                    assert_eq!(
                        result.is_ok(),
                        boot_payload.decode(&mut boot_decoded).is_ok()
                    );
                    if result.is_ok() {
                        assert_eq!(decoded, boot_decoded);
                    }
                }
            }
        }
    }

    #[test]
    fn system_release_binds_three_exact_signed_boot_packages() {
        let bootloader = release_package("org.mrml.library.uefi", "bootloader", "uefi-loader", 2);
        let kernel = release_package("org.mrml.system.kernel", "kernel", "kernel", 3);
        let configuration = release_package(
            "org.mrml.service.config",
            "configuration",
            "configuration",
            4,
        );
        let release =
            build_release(9, &bootloader, &kernel, &configuration, &private_key()).unwrap();
        let decoded = parse_release(&release, true).unwrap();
        assert_eq!(decoded.version, 9);
        assert_eq!(
            decoded.package(BootPackageRole::Kernel).package_digest,
            Sha3_512::digest(&kernel)
        );
        assert!(decoded.binds_exact_package(BootPackageRole::Kernel, 3, &kernel));
        assert!(!decoded.binds_exact_package(BootPackageRole::Kernel, 2, &kernel));
        let mut substituted = kernel.clone();
        substituted[0] ^= 1;
        assert!(!decoded.binds_exact_package(BootPackageRole::Kernel, 3, &substituted));
        let mut tampered = release.clone();
        tampered[200] ^= 1;
        assert!(parse_release(&tampered, true).is_err());
        let wrong = release_package("org.mrml.system.kernel", "kernel", "wrong", 3);
        assert_eq!(
            build_release(9, &bootloader, &wrong, &configuration, &private_key()),
            Err(Error::Architecture)
        );
    }

    #[test]
    fn boot_release_and_exact_packages_reject_every_required_substitution() {
        let bootloader = release_package("org.mrml.library.uefi", "bootloader", "uefi-loader", 2);
        let kernel = release_package("org.mrml.system.kernel", "kernel", "kernel", 3);
        let configuration = release_package(
            "org.mrml.service.config",
            "configuration",
            "configuration",
            4,
        );
        let release =
            build_release(9, &bootloader, &kernel, &configuration, &private_key()).unwrap();
        let decoded = parse_release(&release, true).unwrap();

        let mut modified_payload = kernel.clone();
        let last = modified_payload.len() - 1;
        modified_payload[last] ^= 1;
        assert_ne!(
            Sha3_512::digest(&modified_payload),
            decoded.package(BootPackageRole::Kernel).package_digest
        );
        assert!(parse(&modified_payload, true).is_err());

        let mut wrong_release_digest = release.clone();
        wrong_release_digest[48] ^= 1;
        assert!(parse_release(&wrong_release_digest, true).is_err());
        let mut bad_release_signature = release.clone();
        let signature_byte = bad_release_signature.len() - 1;
        bad_release_signature[signature_byte] ^= 1;
        assert!(parse_release(&bad_release_signature, true).is_err());
        let mut malformed_offsets = release.clone();
        malformed_offsets[32..40].copy_from_slice(&1_u64.to_le_bytes());
        assert!(parse_release(&malformed_offsets, true).is_err());
        assert!(parse_release(&release[..release.len() - 1], true).is_err());

        let wrong_architecture = build(
            "org.mrml.system.kernel",
            "kernel",
            3,
            &[BuildPayload {
                name: "kernel",
                purpose: "kernel",
                architecture: "aarch64",
                compress: false,
                bytes: b"kernel",
            }],
            Some(&private_key()),
        )
        .unwrap();
        assert!(
            build_release(
                9,
                &bootloader,
                &wrong_architecture,
                &configuration,
                &private_key()
            )
            .is_err()
        );
        let wrong_class = release_package("org.mrml.system.kernel", "library", "kernel", 3);
        assert!(
            build_release(9, &bootloader, &wrong_class, &configuration, &private_key()).is_err()
        );
        assert!(build_release(0, &bootloader, &kernel, &configuration, &private_key()).is_err());
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
        let signed_sizes = size_breakdown(&package, bytes.len()).unwrap();
        assert_eq!(signed_sizes.raw_payload_bytes, 14);
        assert_eq!(signed_sizes.stored_payload_bytes, 26);
        assert_eq!(
            signed_sizes.signature_bytes,
            LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES
        );
        assert_eq!(
            signed_sizes.format_metadata_bytes
                + signed_sizes.stored_payload_bytes
                + signed_sizes.signature_bytes,
            signed_sizes.total_bytes
        );
        let unsigned_package = parse(&unsigned, false).unwrap();
        let unsigned_sizes = size_breakdown(&unsigned_package, unsigned.len()).unwrap();
        assert_eq!(unsigned_sizes.signature_bytes, 0);
        assert_eq!(
            unsigned_sizes.format_metadata_bytes + unsigned_sizes.stored_payload_bytes,
            unsigned_sizes.total_bytes
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
