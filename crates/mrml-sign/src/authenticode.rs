use mrml_crypto::Sha256;
use mrml_runtime::Vector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticodeError {
    Truncated,
    InvalidPe,
    TooManySections,
    InvalidCertificateTable,
    InvalidSection,
    Overflow,
    AlreadySigned,
    UnalignedImage,
    EmptyCertificate,
    Allocation,
    InvalidEnclave,
}

const FORCE_INTEGRITY: u16 = 0x0080;
const GUARD_CF: u16 = 0x4000;
// The enclave currently supplies an explicit valid-call-target table without
// compiler-inserted dispatch checks. Do not certify IMAGE_GUARD_CF_INSTRUMENTED
// until the load-config check and dispatch pointers are nonzero and validated.
const REQUIRED_GUARD_FLAGS: u32 = 0x0000_0400 | 0x0000_0800;

pub fn finalize_vbs_enclave(image: &[u8]) -> Result<Vector<u8>, AuthenticodeError> {
    let pe = pe_offset(image)?;
    let optional = pe.checked_add(24).ok_or(AuthenticodeError::Overflow)?;
    let section_count = read_u16(image, pe + 6)? as usize;
    let optional_size = read_u16(image, pe + 20)? as usize;
    if read_u16(image, optional)? != 0x020b
        || optional_size < 240
        || section_count == 0
        || section_count > 32
    {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let image_base = read_u64(image, optional + 24)?;
    let security = optional + 144;
    if read_u32(image, security)? != 0 || read_u32(image, security + 4)? != 0 {
        return Err(AuthenticodeError::AlreadySigned);
    }
    let load_directory = optional + 192;
    let load_rva = read_u32(image, load_directory)?;
    if read_u32(image, load_directory + 4)? != 256 {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let load = rva_file_offset(image, pe, optional, section_count, load_rva, 256, false)?;
    if read_u32(image, load)? != 256
        || image[load + 4..load + 128].iter().any(|byte| *byte != 0)
        || image[load + 148..load + 248].iter().any(|byte| *byte != 0)
    {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let guard_table_va = read_u64(image, load + 128)?;
    let guard_count = read_u64(image, load + 136)?;
    let guard_flags = read_u32(image, load + 144)?;
    if guard_count == 0
        || guard_count > 4096
        || guard_flags != REQUIRED_GUARD_FLAGS
        || guard_table_va < image_base
    {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let guard_bytes = usize::try_from(guard_count)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or(AuthenticodeError::Overflow)?;
    let guard_table_rva = u32::try_from(guard_table_va - image_base)
        .map_err(|_| AuthenticodeError::InvalidEnclave)?;
    let guard_table = rva_file_offset(
        image,
        pe,
        optional,
        section_count,
        guard_table_rva,
        guard_bytes,
        false,
    )?;
    let mut previous = None;
    for index in 0..guard_count as usize {
        let target = read_u32(image, guard_table + index * 4)?;
        if target == 0 || previous.is_some_and(|value| target <= value) {
            return Err(AuthenticodeError::InvalidEnclave);
        }
        rva_file_offset(image, pe, optional, section_count, target, 1, true)?;
        previous = Some(target);
    }
    let enclave_va = read_u64(image, load + 248)?;
    if enclave_va < image_base {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let enclave_rva =
        u32::try_from(enclave_va - image_base).map_err(|_| AuthenticodeError::InvalidEnclave)?;
    let enclave = rva_file_offset(image, pe, optional, section_count, enclave_rva, 80, false)?;
    if read_u32(image, enclave)? != 80
        || read_u32(image, enclave + 4)? != 80
        || read_u32(image, enclave + 8)? != 2
        || read_u32(image, enclave + 12)? != 0
        || read_u32(image, enclave + 16)? != 0
        || read_u32(image, enclave + 20)? != 0
        || read_u64(image, enclave + 64)? == 0
        || !read_u64(image, enclave + 64)?.is_multiple_of(2 * 1024 * 1024)
        || read_u32(image, enclave + 72)? == 0
        || read_u32(image, enclave + 76)? != 1
    {
        return Err(AuthenticodeError::InvalidEnclave);
    }
    let mut output = Vector::new();
    output
        .try_extend_from_slice(image)
        .map_err(|_| AuthenticodeError::Allocation)?;
    let characteristics = read_u16(&output, optional + 70)? | FORCE_INTEGRITY | GUARD_CF;
    output[optional + 70..optional + 72].copy_from_slice(&characteristics.to_le_bytes());
    write_checksum(&mut output)?;
    Ok(output)
}

fn pe_offset(image: &[u8]) -> Result<usize, AuthenticodeError> {
    if read_u16(image, 0)? != 0x5a4d {
        return Err(AuthenticodeError::InvalidPe);
    }
    let pe = read_u32(image, 0x3c)? as usize;
    if read_u32(image, pe)? != 0x0000_4550 || read_u16(image, pe + 4)? != 0x8664 {
        return Err(AuthenticodeError::InvalidPe);
    }
    Ok(pe)
}

fn rva_file_offset(
    image: &[u8],
    pe: usize,
    optional: usize,
    section_count: usize,
    rva: u32,
    length: usize,
    require_executable: bool,
) -> Result<usize, AuthenticodeError> {
    let section_table = optional
        .checked_add(read_u16(image, pe + 20)? as usize)
        .ok_or(AuthenticodeError::Overflow)?;
    for index in 0..section_count {
        let section = section_table
            .checked_add(index.checked_mul(40).ok_or(AuthenticodeError::Overflow)?)
            .ok_or(AuthenticodeError::Overflow)?;
        let virtual_address = read_u32(image, section + 12)?;
        let raw_size = read_u32(image, section + 16)?;
        let raw_offset = read_u32(image, section + 20)?;
        let characteristics = read_u32(image, section + 36)?;
        let relative = match rva.checked_sub(virtual_address) {
            Some(value) => value,
            None => continue,
        };
        let end = (relative as usize)
            .checked_add(length)
            .ok_or(AuthenticodeError::Overflow)?;
        if end <= raw_size as usize && (!require_executable || characteristics & 0x2000_0000 != 0) {
            let at = (raw_offset as usize)
                .checked_add(relative as usize)
                .ok_or(AuthenticodeError::Overflow)?;
            if at
                .checked_add(length)
                .is_some_and(|value| value <= image.len())
            {
                return Ok(at);
            }
        }
    }
    Err(AuthenticodeError::InvalidEnclave)
}

pub fn attach_pkcs7(image: &[u8], certificate: &[u8]) -> Result<Vector<u8>, AuthenticodeError> {
    if certificate.is_empty() {
        return Err(AuthenticodeError::EmptyCertificate);
    }
    if !image.len().is_multiple_of(8) {
        return Err(AuthenticodeError::UnalignedImage);
    }
    // Full parsing also rejects overlays, malformed sections, and existing
    // non-terminal certificate tables before any output is allocated.
    let digest_before = sha256(image)?;
    let security_directory = security_directory_offset(image)?;
    if read_u32(image, security_directory)? != 0 || read_u32(image, security_directory + 4)? != 0 {
        return Err(AuthenticodeError::AlreadySigned);
    }
    let certificate_length = 8usize
        .checked_add(certificate.len())
        .ok_or(AuthenticodeError::Overflow)?;
    let padded_length = certificate_length
        .checked_add(7)
        .map(|length| length & !7)
        .ok_or(AuthenticodeError::Overflow)?;
    let final_length = image
        .len()
        .checked_add(padded_length)
        .ok_or(AuthenticodeError::Overflow)?;
    if certificate_length > u32::MAX as usize
        || padded_length > u32::MAX as usize
        || image.len() > u32::MAX as usize
    {
        return Err(AuthenticodeError::Overflow);
    }
    let mut output = Vector::new();
    output
        .try_extend_from_slice(image)
        .and_then(|_| output.try_resize(final_length, 0))
        .map_err(|_| AuthenticodeError::Allocation)?;
    output[security_directory..security_directory + 4]
        .copy_from_slice(&(image.len() as u32).to_le_bytes());
    output[security_directory + 4..security_directory + 8]
        .copy_from_slice(&(padded_length as u32).to_le_bytes());
    let certificate_at = image.len();
    output[certificate_at..certificate_at + 4]
        .copy_from_slice(&(certificate_length as u32).to_le_bytes());
    output[certificate_at + 4..certificate_at + 6].copy_from_slice(&0x0200u16.to_le_bytes());
    output[certificate_at + 6..certificate_at + 8].copy_from_slice(&0x0002u16.to_le_bytes());
    output[certificate_at + 8..certificate_at + certificate_length].copy_from_slice(certificate);
    write_checksum(&mut output)?;
    if sha256(&output)? != digest_before {
        return Err(AuthenticodeError::InvalidCertificateTable);
    }
    Ok(output)
}

fn security_directory_offset(image: &[u8]) -> Result<usize, AuthenticodeError> {
    if read_u16(image, 0)? != 0x5a4d {
        return Err(AuthenticodeError::InvalidPe);
    }
    let pe = read_u32(image, 0x3c)? as usize;
    if read_u32(image, pe)? != 0x0000_4550 {
        return Err(AuthenticodeError::InvalidPe);
    }
    let optional = pe.checked_add(24).ok_or(AuthenticodeError::Overflow)?;
    if read_u16(image, optional)? != 0x020b {
        return Err(AuthenticodeError::InvalidPe);
    }
    optional.checked_add(144).ok_or(AuthenticodeError::Overflow)
}

fn write_checksum(image: &mut [u8]) -> Result<(), AuthenticodeError> {
    let security = security_directory_offset(image)?;
    let checksum = security
        .checked_sub(80)
        .ok_or(AuthenticodeError::InvalidPe)?;
    image
        .get_mut(checksum..checksum + 4)
        .ok_or(AuthenticodeError::Truncated)?
        .fill(0);
    let mut sum = 0u64;
    for (index, bytes) in image.chunks(2).enumerate() {
        let at = index * 2;
        if (checksum..checksum + 4).contains(&at) {
            continue;
        }
        let word = u16::from_le_bytes([bytes[0], bytes.get(1).copied().unwrap_or(0)]);
        sum = sum.wrapping_add(word as u64);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = sum
        .checked_add(image.len() as u64)
        .ok_or(AuthenticodeError::Overflow)?;
    let checksum_value = u32::try_from(sum).map_err(|_| AuthenticodeError::Overflow)?;
    image[checksum..checksum + 4].copy_from_slice(&checksum_value.to_le_bytes());
    Ok(())
}

pub fn sha256(image: &[u8]) -> Result<[u8; 32], AuthenticodeError> {
    if read_u16(image, 0)? != 0x5a4d {
        return Err(AuthenticodeError::InvalidPe);
    }
    let pe = read_u32(image, 0x3c)? as usize;
    if read_u32(image, pe)? != 0x0000_4550 || read_u16(image, pe + 4)? != 0x8664 {
        return Err(AuthenticodeError::InvalidPe);
    }
    let section_count = read_u16(image, pe + 6)? as usize;
    if section_count == 0 || section_count > 32 {
        return Err(AuthenticodeError::TooManySections);
    }
    let optional_size = read_u16(image, pe + 20)? as usize;
    let optional = pe.checked_add(24).ok_or(AuthenticodeError::Overflow)?;
    if optional_size < 152 || read_u16(image, optional)? != 0x020b {
        return Err(AuthenticodeError::InvalidPe);
    }
    let checksum = optional + 64;
    let security_directory = optional + 144;
    let headers_size = read_u32(image, optional + 60)? as usize;
    if headers_size > image.len() || security_directory + 8 > headers_size {
        return Err(AuthenticodeError::InvalidPe);
    }
    let certificate_offset = read_u32(image, security_directory)? as usize;
    let certificate_size = read_u32(image, security_directory + 4)? as usize;
    let content_end = match (certificate_offset, certificate_size) {
        (0, 0) => image.len(),
        (offset, size)
            if offset % 8 == 0 && size >= 8 && offset.checked_add(size) == Some(image.len()) =>
        {
            offset
        }
        _ => return Err(AuthenticodeError::InvalidCertificateTable),
    };

    let section_table = optional
        .checked_add(optional_size)
        .ok_or(AuthenticodeError::Overflow)?;
    let mut sections = [(0usize, 0usize); 32];
    for (index, slot) in sections.iter_mut().enumerate().take(section_count) {
        let at = section_table
            .checked_add(index.checked_mul(40).ok_or(AuthenticodeError::Overflow)?)
            .ok_or(AuthenticodeError::Overflow)?;
        let size = read_u32(image, at + 16)? as usize;
        let start = read_u32(image, at + 20)? as usize;
        let end = start.checked_add(size).ok_or(AuthenticodeError::Overflow)?;
        if size != 0 && (start < headers_size || end > content_end) {
            return Err(AuthenticodeError::InvalidSection);
        }
        *slot = (start, size);
    }
    sections[..section_count].sort_unstable_by_key(|section| section.0);
    let mut previous_end = headers_size;
    for &(start, size) in &sections[..section_count] {
        if size != 0 && start < previous_end {
            return Err(AuthenticodeError::InvalidSection);
        }
        if size != 0 {
            previous_end = start + size;
        }
    }

    let mut hash = Sha256::new();
    hash.update(&image[..checksum]);
    hash.update(&image[checksum + 4..security_directory]);
    hash.update(&image[security_directory + 8..headers_size]);
    let mut hashed = headers_size;
    for &(start, size) in &sections[..section_count] {
        if size != 0 {
            hash.update(&image[start..start + size]);
            hashed = hashed
                .checked_add(size)
                .ok_or(AuthenticodeError::Overflow)?;
        }
    }
    if hashed > content_end {
        return Err(AuthenticodeError::InvalidSection);
    }
    hash.update(&image[hashed..content_end]);
    Ok(hash.finalize())
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, AuthenticodeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(AuthenticodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, AuthenticodeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(AuthenticodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, AuthenticodeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(AuthenticodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> [u8; 1024] {
        let mut image = [0u8; 1024];
        image[..2].copy_from_slice(&0x5a4d_u16.to_le_bytes());
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        image[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x020b_u16.to_le_bytes());
        image[0xd4..0xd8].copy_from_slice(&512u32.to_le_bytes());
        image[0x198..0x19c].copy_from_slice(&512u32.to_le_bytes());
        image[0x19c..0x1a0].copy_from_slice(&512u32.to_le_bytes());
        image[512..].fill(0x5a);
        image
    }

    fn enclave_image() -> [u8; 2048] {
        let mut image = [0u8; 2048];
        image[..2].copy_from_slice(&0x5a4d_u16.to_le_bytes());
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        image[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x020b_u16.to_le_bytes());
        image[0xb0..0xb8].copy_from_slice(&0x0001_8000_0000_u64.to_le_bytes());
        image[0xd4..0xd8].copy_from_slice(&512u32.to_le_bytes());
        image[0x158..0x15c].copy_from_slice(&0x1100u32.to_le_bytes());
        image[0x15c..0x160].copy_from_slice(&256u32.to_le_bytes());
        let section = 0x188;
        image[section..section + 6].copy_from_slice(b".rdata");
        image[section + 8..section + 12].copy_from_slice(&1536u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&1536u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let load = 0x300;
        image[load..load + 4].copy_from_slice(&256u32.to_le_bytes());
        image[load + 128..load + 136].copy_from_slice(&0x0001_8000_1400_u64.to_le_bytes());
        image[load + 136..load + 144].copy_from_slice(&2u64.to_le_bytes());
        image[load + 144..load + 148].copy_from_slice(&REQUIRED_GUARD_FLAGS.to_le_bytes());
        image[load + 248..load + 256].copy_from_slice(&0x0001_8000_1300_u64.to_le_bytes());
        let config = 0x500;
        image[config..config + 4].copy_from_slice(&80u32.to_le_bytes());
        image[config + 4..config + 8].copy_from_slice(&80u32.to_le_bytes());
        image[config + 8..config + 12].copy_from_slice(&2u32.to_le_bytes());
        image[config + 64..config + 72].copy_from_slice(&(2u64 * 1024 * 1024).to_le_bytes());
        image[config + 72..config + 76].copy_from_slice(&1u32.to_le_bytes());
        image[config + 76..config + 80].copy_from_slice(&1u32.to_le_bytes());
        image[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x604..0x608].copy_from_slice(&0x1010u32.to_le_bytes());
        image
    }

    #[test]
    fn excludes_checksum_and_certificate_directory_fields() {
        let mut original = image().to_vec();
        original.extend_from_slice(&[8, 0, 0, 0, 0, 2, 2, 0]);
        original[0x128..0x12c].copy_from_slice(&1024u32.to_le_bytes());
        original[0x12c..0x130].copy_from_slice(&8u32.to_le_bytes());
        let expected = sha256(&original).unwrap();
        let mut changed = original.clone();
        changed[0xd8..0xdc].copy_from_slice(&0xfeed_beef_u32.to_le_bytes());
        changed[1028..].fill(0xa5);
        assert_eq!(sha256(&changed), Ok(expected));
        changed[600] ^= 1;
        assert_ne!(sha256(&changed), Ok(expected));
    }

    #[test]
    fn attaches_one_canonical_pkcs7_certificate_without_changing_digest() {
        let original = image();
        let expected = sha256(&original).unwrap();
        let attached = attach_pkcs7(&original, &[0x30, 1, 0]).unwrap();
        assert_eq!(attached.len(), 1040);
        assert_eq!(&attached[0x128..0x12c], &1024u32.to_le_bytes());
        assert_eq!(&attached[0x12c..0x130], &16u32.to_le_bytes());
        assert_eq!(&attached[1024..1028], &11u32.to_le_bytes());
        assert_eq!(&attached[1028..1030], &0x0200u16.to_le_bytes());
        assert_eq!(&attached[1030..1032], &0x0002u16.to_le_bytes());
        assert_eq!(sha256(&attached), Ok(expected));
        assert!(matches!(
            attach_pkcs7(&attached, &[1]),
            Err(AuthenticodeError::AlreadySigned)
        ));
    }

    #[test]
    fn finalizes_only_a_canonical_strict_vbs_image() {
        let image = enclave_image();
        let finalized = finalize_vbs_enclave(&image).unwrap();
        assert_eq!(read_u16(&finalized, 0xde).unwrap() & 0x4080, 0x4080);
        assert_ne!(read_u32(&finalized, 0xd8).unwrap(), 0);
        let mut unsorted = image;
        unsorted[0x604..0x608].copy_from_slice(&0x0ff0u32.to_le_bytes());
        assert_eq!(
            finalize_vbs_enclave(&unsorted),
            Err(AuthenticodeError::InvalidEnclave)
        );
        let mut debug = image;
        debug[0x508..0x50c].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            finalize_vbs_enclave(&debug),
            Err(AuthenticodeError::InvalidEnclave)
        );
    }
}
