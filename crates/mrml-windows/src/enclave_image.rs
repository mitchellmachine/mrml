const DOS_MAGIC: u16 = 0x5a4d;
const PE_SIGNATURE: u32 = 0x0000_4550;
const MACHINE_X86_64: u16 = 0x8664;
const PE32_PLUS: u16 = 0x020b;
const SECTION_EXECUTE: u32 = 0x2000_0000;
const MAX_SECTIONS: usize = 32;
const MAX_EXPORTS: usize = 65_536;
const MAX_EXPORT_NAME: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VbsEnclaveImageError {
    Truncated,
    InvalidImage,
    InvalidExportName,
    ExportNotFound,
    ForwardedExport,
    ExportNotExecutable,
}

/// An image-relative address proven to name an executable, non-forwarded
/// export in a bounded x86_64 PE image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbsEnclaveRoutineRva(u32);

impl VbsEnclaveRoutineRva {
    pub const fn get(self) -> u32 {
        self.0
    }
}

pub fn vbs_enclave_export_rva(
    image: &[u8],
    export_name: &[u8],
) -> Result<VbsEnclaveRoutineRva, VbsEnclaveImageError> {
    if export_name.is_empty() || export_name.len() > MAX_EXPORT_NAME || export_name.contains(&0) {
        return Err(VbsEnclaveImageError::InvalidExportName);
    }
    if read_u16(image, 0)? != DOS_MAGIC {
        return Err(VbsEnclaveImageError::InvalidImage);
    }
    let pe =
        usize::try_from(read_u32(image, 0x3c)?).map_err(|_| VbsEnclaveImageError::InvalidImage)?;
    if pe < 0x40
        || read_u32(image, pe)? != PE_SIGNATURE
        || read_u16(image, pe + 4)? != MACHINE_X86_64
    {
        return Err(VbsEnclaveImageError::InvalidImage);
    }
    let section_count = usize::from(read_u16(image, pe + 6)?);
    let optional_size = usize::from(read_u16(image, pe + 20)?);
    let optional = pe
        .checked_add(24)
        .ok_or(VbsEnclaveImageError::InvalidImage)?;
    let section_table = optional
        .checked_add(optional_size)
        .ok_or(VbsEnclaveImageError::InvalidImage)?;
    if section_count == 0
        || section_count > MAX_SECTIONS
        || optional_size < 120
        || read_u16(image, optional)? != PE32_PLUS
        || read_u32(image, optional + 108)? == 0
    {
        return Err(VbsEnclaveImageError::InvalidImage);
    }
    checked_slice(image, section_table, section_count * 40)?;
    let image_size = read_u32(image, optional + 56)?;
    let headers_size = read_u32(image, optional + 60)?;
    let export_rva = read_u32(image, optional + 112)?;
    let export_size = read_u32(image, optional + 116)?;
    if image_size == 0
        || headers_size == 0
        || export_rva == 0
        || export_size < 40
        || export_rva
            .checked_add(export_size)
            .is_none_or(|end| end > image_size)
    {
        return Err(VbsEnclaveImageError::InvalidImage);
    }
    let export = rva_to_file(
        image,
        section_table,
        section_count,
        headers_size,
        export_rva,
        40,
    )?;
    let function_count = usize::try_from(read_u32(image, export + 20)?)
        .map_err(|_| VbsEnclaveImageError::InvalidImage)?;
    let name_count = usize::try_from(read_u32(image, export + 24)?)
        .map_err(|_| VbsEnclaveImageError::InvalidImage)?;
    if function_count == 0
        || function_count > MAX_EXPORTS
        || name_count == 0
        || name_count > function_count
    {
        return Err(VbsEnclaveImageError::InvalidImage);
    }
    let functions_rva = read_u32(image, export + 28)?;
    let names_rva = read_u32(image, export + 32)?;
    let ordinals_rva = read_u32(image, export + 36)?;
    let functions = rva_to_file(
        image,
        section_table,
        section_count,
        headers_size,
        functions_rva,
        function_count * 4,
    )?;
    let names = rva_to_file(
        image,
        section_table,
        section_count,
        headers_size,
        names_rva,
        name_count * 4,
    )?;
    let ordinals = rva_to_file(
        image,
        section_table,
        section_count,
        headers_size,
        ordinals_rva,
        name_count * 2,
    )?;
    for index in 0..name_count {
        let name_rva = read_u32(image, names + index * 4)?;
        let name_offset = rva_to_file(
            image,
            section_table,
            section_count,
            headers_size,
            name_rva,
            1,
        )?;
        if bounded_c_string(image, name_offset, MAX_EXPORT_NAME)? != export_name {
            continue;
        }
        let ordinal = usize::from(read_u16(image, ordinals + index * 2)?);
        if ordinal >= function_count {
            return Err(VbsEnclaveImageError::InvalidImage);
        }
        let routine_rva = read_u32(image, functions + ordinal * 4)?;
        if (export_rva..export_rva + export_size).contains(&routine_rva) {
            return Err(VbsEnclaveImageError::ForwardedExport);
        }
        if routine_rva >= image_size
            || !rva_is_executable(section_table, section_count, image, routine_rva)?
        {
            return Err(VbsEnclaveImageError::ExportNotExecutable);
        }
        return Ok(VbsEnclaveRoutineRva(routine_rva));
    }
    Err(VbsEnclaveImageError::ExportNotFound)
}

fn rva_is_executable(
    section_table: usize,
    section_count: usize,
    image: &[u8],
    rva: u32,
) -> Result<bool, VbsEnclaveImageError> {
    for index in 0..section_count {
        let section = section_table + index * 40;
        let virtual_size = read_u32(image, section + 8)?;
        let virtual_address = read_u32(image, section + 12)?;
        if virtual_size != 0
            && (virtual_address..virtual_address.saturating_add(virtual_size)).contains(&rva)
        {
            return Ok(read_u32(image, section + 36)? & SECTION_EXECUTE != 0);
        }
    }
    Ok(false)
}

fn rva_to_file(
    image: &[u8],
    section_table: usize,
    section_count: usize,
    headers_size: u32,
    rva: u32,
    bytes: usize,
) -> Result<usize, VbsEnclaveImageError> {
    if rva < headers_size {
        let offset = usize::try_from(rva).map_err(|_| VbsEnclaveImageError::InvalidImage)?;
        checked_slice(image, offset, bytes)?;
        return Ok(offset);
    }
    for index in 0..section_count {
        let section = section_table + index * 40;
        let virtual_address = read_u32(image, section + 12)?;
        let raw_size = read_u32(image, section + 16)?;
        let raw_offset = read_u32(image, section + 20)?;
        let Some(relative) = rva.checked_sub(virtual_address) else {
            continue;
        };
        let bytes_u32 = u32::try_from(bytes).map_err(|_| VbsEnclaveImageError::InvalidImage)?;
        if relative
            .checked_add(bytes_u32)
            .is_none_or(|end| end > raw_size)
        {
            continue;
        }
        let offset = usize::try_from(raw_offset)
            .ok()
            .and_then(|start| start.checked_add(relative as usize))
            .ok_or(VbsEnclaveImageError::InvalidImage)?;
        checked_slice(image, offset, bytes)?;
        return Ok(offset);
    }
    Err(VbsEnclaveImageError::InvalidImage)
}

fn bounded_c_string(
    image: &[u8],
    offset: usize,
    maximum: usize,
) -> Result<&[u8], VbsEnclaveImageError> {
    let end = offset
        .checked_add(maximum + 1)
        .map_or(image.len(), |end| end.min(image.len()));
    let bytes = image
        .get(offset..end)
        .ok_or(VbsEnclaveImageError::Truncated)?;
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(VbsEnclaveImageError::InvalidImage)?;
    Ok(&bytes[..length])
}

fn checked_slice(image: &[u8], offset: usize, bytes: usize) -> Result<&[u8], VbsEnclaveImageError> {
    let end = offset
        .checked_add(bytes)
        .ok_or(VbsEnclaveImageError::Truncated)?;
    image
        .get(offset..end)
        .ok_or(VbsEnclaveImageError::Truncated)
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, VbsEnclaveImageError> {
    let bytes: [u8; 2] = checked_slice(image, offset, 2)?
        .try_into()
        .map_err(|_| VbsEnclaveImageError::Truncated)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, VbsEnclaveImageError> {
    let bytes: [u8; 4] = checked_slice(image, offset, 4)?
        .try_into()
        .map_err(|_| VbsEnclaveImageError::Truncated)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn export_image() -> [u8; 0x600] {
        let mut image = [0u8; 0x600];
        write_u16(&mut image, 0, DOS_MAGIC);
        write_u32(&mut image, 0x3c, 0x80);
        write_u32(&mut image, 0x80, PE_SIGNATURE);
        write_u16(&mut image, 0x84, MACHINE_X86_64);
        write_u16(&mut image, 0x86, 2);
        write_u16(&mut image, 0x94, 0xf0);
        let optional = 0x98;
        write_u16(&mut image, optional, PE32_PLUS);
        write_u32(&mut image, optional + 56, 0x3000);
        write_u32(&mut image, optional + 60, 0x200);
        write_u32(&mut image, optional + 108, 16);
        write_u32(&mut image, optional + 112, 0x2000);
        write_u32(&mut image, optional + 116, 0x100);
        let sections = optional + 0xf0;
        image[sections..sections + 5].copy_from_slice(b".text");
        write_u32(&mut image, sections + 8, 0x100);
        write_u32(&mut image, sections + 12, 0x1000);
        write_u32(&mut image, sections + 16, 0x200);
        write_u32(&mut image, sections + 20, 0x200);
        write_u32(&mut image, sections + 36, SECTION_EXECUTE | 0x4000_0000);
        let edata = sections + 40;
        image[edata..edata + 6].copy_from_slice(b".edata");
        write_u32(&mut image, edata + 8, 0x100);
        write_u32(&mut image, edata + 12, 0x2000);
        write_u32(&mut image, edata + 16, 0x200);
        write_u32(&mut image, edata + 20, 0x400);
        write_u32(&mut image, edata + 36, 0x4000_0000);
        let export = 0x400;
        write_u32(&mut image, export + 20, 1);
        write_u32(&mut image, export + 24, 1);
        write_u32(&mut image, export + 28, 0x2040);
        write_u32(&mut image, export + 32, 0x2044);
        write_u32(&mut image, export + 36, 0x2048);
        write_u32(&mut image, 0x440, 0x1000);
        write_u32(&mut image, 0x444, 0x2050);
        write_u16(&mut image, 0x448, 0);
        image[0x450..0x466].copy_from_slice(b"mrml_launch_authority\0");
        image
    }

    #[test]
    fn resolves_exact_executable_non_forwarded_export() {
        let image = export_image();
        assert_eq!(
            vbs_enclave_export_rva(&image, b"mrml_launch_authority"),
            Ok(VbsEnclaveRoutineRva(0x1000))
        );
        assert_eq!(
            vbs_enclave_export_rva(&image, b"mrml_launch"),
            Err(VbsEnclaveImageError::ExportNotFound)
        );
    }

    #[test]
    fn rejects_forwarded_and_non_executable_exports() {
        let mut forwarded = export_image();
        write_u32(&mut forwarded, 0x440, 0x2060);
        assert_eq!(
            vbs_enclave_export_rva(&forwarded, b"mrml_launch_authority"),
            Err(VbsEnclaveImageError::ForwardedExport)
        );
        let mut data = export_image();
        write_u32(&mut data, 0x440, 0x2100);
        assert_eq!(
            vbs_enclave_export_rva(&data, b"mrml_launch_authority"),
            Err(VbsEnclaveImageError::ExportNotExecutable)
        );
    }

    #[test]
    fn malformed_counts_and_names_fail_closed() {
        let mut image = export_image();
        write_u32(&mut image, 0x400 + 24, (MAX_EXPORTS + 1) as u32);
        assert_eq!(
            vbs_enclave_export_rva(&image, b"mrml_launch_authority"),
            Err(VbsEnclaveImageError::InvalidImage)
        );
        assert_eq!(
            vbs_enclave_export_rva(&export_image(), b"bad\0name"),
            Err(VbsEnclaveImageError::InvalidExportName)
        );
    }
}
