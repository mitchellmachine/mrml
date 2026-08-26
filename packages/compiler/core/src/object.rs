use crate::MachineCode;

const ELF_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_SECTION_COUNT: usize = 5;
const ELF_SECTION_NAMES: &[u8] = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";

const COFF_HEADER_BYTES: usize = 20;
const COFF_SECTION_HEADER_BYTES: usize = 40;
pub const MAX_X86_64_RELOCATIONS: usize = 8;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectError {
    EmptySymbol,
    SymbolContainsNul,
    OutputTooSmall,
    OffsetOverflow,
    InvalidRelocationOffset,
    InvalidReadonlyDataOffset,
    TooManyRelocations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64ReadonlyRelocation {
    pub offset: usize,
    pub data_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64PcRelativeRelocation<'symbol> {
    pub offset: usize,
    pub symbol: &'symbol str,
    pub kind: X86_64PcRelativeRelocationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64PcRelativeRelocationKind {
    Branch,
    Data,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectFile<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
}

impl<const MAX_BYTES: usize> ObjectFile<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub const fn len(&self) -> usize {
        self.length
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

struct Writer<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    position: usize,
}

impl<const MAX_BYTES: usize> Writer<MAX_BYTES> {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_BYTES],
            position: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), ObjectError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(ObjectError::OffsetOverflow)?;
        let output = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ObjectError::OutputTooSmall)?;
        output.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn zeros(&mut self, length: usize) -> Result<(), ObjectError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ObjectError::OffsetOverflow)?;
        self.bytes
            .get(self.position..end)
            .ok_or(ObjectError::OutputTooSmall)?;
        self.position = end;
        Ok(())
    }

    fn align(&mut self, alignment: usize) -> Result<(), ObjectError> {
        let remainder = self.position % alignment;
        if remainder == 0 {
            Ok(())
        } else {
            self.zeros(alignment - remainder)
        }
    }

    fn u16(&mut self, value: u16) -> Result<(), ObjectError> {
        self.write(&value.to_le_bytes())
    }

    fn i16(&mut self, value: i16) -> Result<(), ObjectError> {
        self.write(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), ObjectError> {
        self.write(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ObjectError> {
        self.write(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), ObjectError> {
        self.write(&value.to_le_bytes())
    }

    fn patch_u64(&mut self, offset: usize, value: u64) -> Result<(), ObjectError> {
        let end = offset.checked_add(8).ok_or(ObjectError::OffsetOverflow)?;
        self.bytes
            .get_mut(offset..end)
            .ok_or(ObjectError::OutputTooSmall)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn patch_i32(&mut self, offset: usize, value: i32) -> Result<(), ObjectError> {
        let end = offset.checked_add(4).ok_or(ObjectError::OffsetOverflow)?;
        self.bytes
            .get_mut(offset..end)
            .ok_or(ObjectError::OutputTooSmall)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn finish(self) -> ObjectFile<MAX_BYTES> {
        ObjectFile {
            bytes: self.bytes,
            length: self.position,
        }
    }
}

fn validate_symbol(symbol: &str) -> Result<(), ObjectError> {
    if symbol.is_empty() {
        Err(ObjectError::EmptySymbol)
    } else if symbol.as_bytes().contains(&0) {
        Err(ObjectError::SymbolContainsNul)
    } else {
        Ok(())
    }
}

fn validate_relocations<const MAX_CODE_BYTES: usize>(
    code: &MachineCode<MAX_CODE_BYTES>,
    relocations: &[X86_64PcRelativeRelocation<'_>],
) -> Result<(), ObjectError> {
    if relocations.len() > MAX_X86_64_RELOCATIONS {
        return Err(ObjectError::TooManyRelocations);
    }
    for relocation in relocations {
        validate_symbol(relocation.symbol)?;
        relocation
            .offset
            .checked_add(4)
            .filter(|end| *end <= code.len())
            .ok_or(ObjectError::InvalidRelocationOffset)?;
    }
    Ok(())
}

fn validate_readonly_relocations<const MAX_CODE_BYTES: usize>(
    code: &MachineCode<MAX_CODE_BYTES>,
    data: &[u8],
    relocations: &[X86_64ReadonlyRelocation],
) -> Result<(), ObjectError> {
    if relocations.len() > MAX_X86_64_RELOCATIONS {
        return Err(ObjectError::TooManyRelocations);
    }
    for relocation in relocations {
        relocation
            .offset
            .checked_add(4)
            .filter(|end| *end <= code.len())
            .ok_or(ObjectError::InvalidRelocationOffset)?;
        if relocation.data_offset > data.len() {
            return Err(ObjectError::InvalidReadonlyDataOffset);
        }
        i32::try_from(relocation.data_offset).map_err(|_| ObjectError::OffsetOverflow)?;
    }
    Ok(())
}

pub fn emit_elf64_x86_64<const MAX_OBJECT_BYTES: usize, const MAX_CODE_BYTES: usize>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    let mut writer = Writer::new();

    writer.write(b"\x7fELF")?;
    writer.write(&[2, 1, 1, 0, 0])?;
    writer.zeros(7)?;
    writer.u16(1)?;
    writer.u16(62)?;
    writer.u32(1)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u32(0)?;
    writer.u16(ELF_HEADER_BYTES as u16)?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(ELF_SECTION_HEADER_BYTES as u16)?;
    writer.u16(ELF_SECTION_COUNT as u16)?;
    writer.u16(4)?;

    let text_offset = writer.position;
    writer.write(code.bytes())?;
    writer.align(8)?;
    let symbol_offset = writer.position;
    writer.zeros(ELF_SYMBOL_BYTES)?;
    writer.u32(1)?;
    writer.write(&[0x12, 0])?;
    writer.u16(1)?;
    writer.u64(0)?;
    writer.u64(to_u64(code.len())?)?;
    let string_offset = writer.position;
    writer.write(&[0])?;
    writer.write(symbol.as_bytes())?;
    writer.write(&[0])?;
    let string_size = writer.position - string_offset;
    let section_name_offset = writer.position;
    writer.write(ELF_SECTION_NAMES)?;
    let section_name_size = writer.position - section_name_offset;
    writer.align(8)?;
    let section_headers_offset = writer.position;
    writer.patch_u64(40, to_u64(section_headers_offset)?)?;

    writer.zeros(ELF_SECTION_HEADER_BYTES)?;
    elf_section(&mut writer, 1, 1, 6, text_offset, code.len(), 0, 0, 16, 0)?;
    elf_section(
        &mut writer,
        7,
        2,
        0,
        symbol_offset,
        ELF_SYMBOL_BYTES * 2,
        3,
        1,
        8,
        ELF_SYMBOL_BYTES,
    )?;
    elf_section(
        &mut writer,
        15,
        3,
        0,
        string_offset,
        string_size,
        0,
        0,
        1,
        0,
    )?;
    elf_section(
        &mut writer,
        23,
        3,
        0,
        section_name_offset,
        section_name_size,
        0,
        0,
        1,
        0,
    )?;
    Ok(writer.finish())
}

pub fn emit_elf64_x86_64_with_relocation<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    relocation: X86_64PcRelativeRelocation<'_>,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    emit_elf64_x86_64_with_relocations(symbol, code, &[relocation])
}

pub fn emit_elf64_x86_64_with_relocations<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    relocations: &[X86_64PcRelativeRelocation<'_>],
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    if relocations.is_empty() {
        return emit_elf64_x86_64(symbol, code);
    }
    validate_relocations(code, relocations)?;
    const SECTION_NAMES: &[u8] = b"\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0";
    let mut writer = Writer::new();

    writer.write(b"\x7fELF")?;
    writer.write(&[2, 1, 1, 0, 0])?;
    writer.zeros(7)?;
    writer.u16(1)?;
    writer.u16(62)?;
    writer.u32(1)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u32(0)?;
    writer.u16(ELF_HEADER_BYTES as u16)?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(ELF_SECTION_HEADER_BYTES as u16)?;
    writer.u16(6)?;
    writer.u16(5)?;

    let text_offset = writer.position;
    writer.write(code.bytes())?;
    writer.align(8)?;
    let relocation_offset = writer.position;
    for (index, relocation) in relocations.iter().enumerate() {
        writer.u64(to_u64(relocation.offset)?)?;
        let relocation_type = match relocation.kind {
            X86_64PcRelativeRelocationKind::Branch => 4,
            X86_64PcRelativeRelocationKind::Data => 2,
        };
        let symbol_index = 2usize
            .checked_add(index)
            .ok_or(ObjectError::OffsetOverflow)?;
        writer.u64((to_u64(symbol_index)? << 32) | relocation_type)?;
        writer.i64(-4)?;
    }
    let symbol_offset = writer.position;
    writer.zeros(ELF_SYMBOL_BYTES)?;
    writer.u32(1)?;
    writer.write(&[0x12, 0])?;
    writer.u16(1)?;
    writer.u64(0)?;
    writer.u64(to_u64(code.len())?)?;
    let mut external_name = 1usize
        .checked_add(symbol.len())
        .and_then(|offset| offset.checked_add(1))
        .ok_or(ObjectError::OffsetOverflow)?;
    for relocation in relocations {
        writer.u32(to_u32(external_name)?)?;
        writer.write(&[
            match relocation.kind {
                X86_64PcRelativeRelocationKind::Branch => 0x12,
                X86_64PcRelativeRelocationKind::Data => 0x11,
            },
            0,
        ])?;
        writer.u16(0)?;
        writer.u64(0)?;
        writer.u64(0)?;
        external_name = external_name
            .checked_add(relocation.symbol.len())
            .and_then(|offset| offset.checked_add(1))
            .ok_or(ObjectError::OffsetOverflow)?;
    }
    let string_offset = writer.position;
    writer.write(&[0])?;
    writer.write(symbol.as_bytes())?;
    writer.write(&[0])?;
    for relocation in relocations {
        writer.write(relocation.symbol.as_bytes())?;
        writer.write(&[0])?;
    }
    let string_size = writer.position - string_offset;
    let section_name_offset = writer.position;
    writer.write(SECTION_NAMES)?;
    let section_name_size = writer.position - section_name_offset;
    writer.align(8)?;
    let section_headers_offset = writer.position;
    writer.patch_u64(40, to_u64(section_headers_offset)?)?;

    writer.zeros(ELF_SECTION_HEADER_BYTES)?;
    elf_section(&mut writer, 1, 1, 6, text_offset, code.len(), 0, 0, 16, 0)?;
    let relocation_bytes = 24usize
        .checked_mul(relocations.len())
        .ok_or(ObjectError::OffsetOverflow)?;
    elf_section(
        &mut writer,
        7,
        4,
        0,
        relocation_offset,
        relocation_bytes,
        3,
        1,
        8,
        24,
    )?;
    elf_section(
        &mut writer,
        18,
        2,
        0,
        symbol_offset,
        ELF_SYMBOL_BYTES
            .checked_mul(
                2usize
                    .checked_add(relocations.len())
                    .ok_or(ObjectError::OffsetOverflow)?,
            )
            .ok_or(ObjectError::OffsetOverflow)?,
        4,
        1,
        8,
        ELF_SYMBOL_BYTES,
    )?;
    elf_section(
        &mut writer,
        26,
        3,
        0,
        string_offset,
        string_size,
        0,
        0,
        1,
        0,
    )?;
    elf_section(
        &mut writer,
        34,
        3,
        0,
        section_name_offset,
        section_name_size,
        0,
        0,
        1,
        0,
    )?;
    Ok(writer.finish())
}

pub fn emit_elf64_x86_64_with_readonly_data<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    data: &[u8],
    relocations: &[X86_64ReadonlyRelocation],
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    validate_readonly_relocations(code, data, relocations)?;
    const SECTION_NAMES: &[u8] = b"\0.text\0.rela.text\0.rodata\0.symtab\0.strtab\0.shstrtab\0";
    let mut writer = Writer::new();

    writer.write(b"\x7fELF")?;
    writer.write(&[2, 1, 1, 0, 0])?;
    writer.zeros(7)?;
    writer.u16(1)?;
    writer.u16(62)?;
    writer.u32(1)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u32(0)?;
    writer.u16(ELF_HEADER_BYTES as u16)?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(ELF_SECTION_HEADER_BYTES as u16)?;
    writer.u16(7)?;
    writer.u16(6)?;

    let text_offset = writer.position;
    writer.write(code.bytes())?;
    writer.align(8)?;
    let relocation_offset = writer.position;
    for relocation in relocations {
        writer.u64(to_u64(relocation.offset)?)?;
        writer.u64((1u64 << 32) | 2)?;
        let addend = i64::try_from(relocation.data_offset)
            .map_err(|_| ObjectError::OffsetOverflow)?
            .checked_sub(4)
            .ok_or(ObjectError::OffsetOverflow)?;
        writer.i64(addend)?;
    }
    let data_offset = writer.position;
    writer.write(data)?;
    writer.align(8)?;
    let symbol_offset = writer.position;
    writer.zeros(ELF_SYMBOL_BYTES)?;
    writer.u32(0)?;
    writer.write(&[0x03, 0])?;
    writer.u16(3)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u32(1)?;
    writer.write(&[0x12, 0])?;
    writer.u16(1)?;
    writer.u64(0)?;
    writer.u64(to_u64(code.len())?)?;
    let string_offset = writer.position;
    writer.write(&[0])?;
    writer.write(symbol.as_bytes())?;
    writer.write(&[0])?;
    let string_size = writer.position - string_offset;
    let section_name_offset = writer.position;
    writer.write(SECTION_NAMES)?;
    let section_name_size = writer.position - section_name_offset;
    writer.align(8)?;
    let section_headers_offset = writer.position;
    writer.patch_u64(40, to_u64(section_headers_offset)?)?;

    writer.zeros(ELF_SECTION_HEADER_BYTES)?;
    elf_section(&mut writer, 1, 1, 6, text_offset, code.len(), 0, 0, 16, 0)?;
    elf_section(
        &mut writer,
        7,
        4,
        0,
        relocation_offset,
        24usize
            .checked_mul(relocations.len())
            .ok_or(ObjectError::OffsetOverflow)?,
        4,
        1,
        8,
        24,
    )?;
    elf_section(&mut writer, 18, 1, 2, data_offset, data.len(), 0, 0, 1, 0)?;
    elf_section(
        &mut writer,
        26,
        2,
        0,
        symbol_offset,
        ELF_SYMBOL_BYTES * 3,
        5,
        2,
        8,
        ELF_SYMBOL_BYTES,
    )?;
    elf_section(
        &mut writer,
        34,
        3,
        0,
        string_offset,
        string_size,
        0,
        0,
        1,
        0,
    )?;
    elf_section(
        &mut writer,
        42,
        3,
        0,
        section_name_offset,
        section_name_size,
        0,
        0,
        1,
        0,
    )?;
    Ok(writer.finish())
}

#[allow(clippy::too_many_arguments)]
fn elf_section<const MAX_BYTES: usize>(
    writer: &mut Writer<MAX_BYTES>,
    name: u32,
    section_type: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: usize,
) -> Result<(), ObjectError> {
    writer.u32(name)?;
    writer.u32(section_type)?;
    writer.u64(flags)?;
    writer.u64(0)?;
    writer.u64(to_u64(offset)?)?;
    writer.u64(to_u64(size)?)?;
    writer.u32(link)?;
    writer.u32(info)?;
    writer.u64(alignment)?;
    writer.u64(to_u64(entry_size)?)
}

pub fn emit_x86_64_coff<const MAX_OBJECT_BYTES: usize, const MAX_CODE_BYTES: usize>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    let raw_data_offset = COFF_HEADER_BYTES + COFF_SECTION_HEADER_BYTES;
    let symbol_offset = raw_data_offset
        .checked_add(code.len())
        .ok_or(ObjectError::OffsetOverflow)?;
    let mut writer = Writer::new();

    writer.u16(0x8664)?;
    writer.u16(1)?;
    writer.u32(0)?;
    writer.u32(to_u32(symbol_offset)?)?;
    writer.u32(1)?;
    writer.u16(0)?;
    writer.u16(0)?;

    writer.write(b".text\0\0\0")?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(to_u32(code.len())?)?;
    writer.u32(to_u32(raw_data_offset)?)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u32(0x6000_0020)?;
    writer.write(code.bytes())?;

    if symbol.len() <= 8 {
        writer.write(symbol.as_bytes())?;
        writer.zeros(8 - symbol.len())?;
    } else {
        writer.u32(0)?;
        writer.u32(4)?;
    }
    writer.u32(0)?;
    writer.i16(1)?;
    writer.u16(0x20)?;
    writer.write(&[2, 0])?;
    if symbol.len() <= 8 {
        writer.u32(4)?;
    } else {
        let string_table_size = 4usize
            .checked_add(symbol.len())
            .and_then(|size| size.checked_add(1))
            .ok_or(ObjectError::OffsetOverflow)?;
        writer.u32(to_u32(string_table_size)?)?;
        writer.write(symbol.as_bytes())?;
        writer.write(&[0])?;
    }
    Ok(writer.finish())
}

pub fn emit_x86_64_coff_with_relocation<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    relocation: X86_64PcRelativeRelocation<'_>,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    emit_x86_64_coff_with_relocations(symbol, code, &[relocation])
}

pub fn emit_x86_64_coff_with_relocations<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    relocations: &[X86_64PcRelativeRelocation<'_>],
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    if relocations.is_empty() {
        return emit_x86_64_coff(symbol, code);
    }
    validate_relocations(code, relocations)?;
    let raw_data_offset = COFF_HEADER_BYTES + COFF_SECTION_HEADER_BYTES;
    let relocation_offset = raw_data_offset
        .checked_add(code.len())
        .ok_or(ObjectError::OffsetOverflow)?;
    let symbol_offset = relocation_offset
        .checked_add(
            10usize
                .checked_mul(relocations.len())
                .ok_or(ObjectError::OffsetOverflow)?,
        )
        .ok_or(ObjectError::OffsetOverflow)?;
    let symbol_long = symbol.len() > 8;
    let symbol_string_bytes = if symbol_long {
        symbol
            .len()
            .checked_add(1)
            .ok_or(ObjectError::OffsetOverflow)?
    } else {
        0
    };
    let mut string_table_size = 4usize
        .checked_add(symbol_string_bytes)
        .ok_or(ObjectError::OffsetOverflow)?;
    for relocation in relocations {
        if relocation.symbol.len() > 8 {
            string_table_size = string_table_size
                .checked_add(relocation.symbol.len())
                .and_then(|size| size.checked_add(1))
                .ok_or(ObjectError::OffsetOverflow)?;
        }
    }
    let mut writer = Writer::new();

    writer.u16(0x8664)?;
    writer.u16(1)?;
    writer.u32(0)?;
    writer.u32(to_u32(symbol_offset)?)?;
    writer.u32(to_u32(
        1usize
            .checked_add(relocations.len())
            .ok_or(ObjectError::OffsetOverflow)?,
    )?)?;
    writer.u16(0)?;
    writer.u16(0)?;

    writer.write(b".text\0\0\0")?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(to_u32(code.len())?)?;
    writer.u32(to_u32(raw_data_offset)?)?;
    writer.u32(to_u32(relocation_offset)?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(relocations.len()).map_err(|_| ObjectError::OffsetOverflow)?)?;
    writer.u16(0)?;
    writer.u32(0x6000_0020)?;
    writer.write(code.bytes())?;
    for (index, relocation) in relocations.iter().enumerate() {
        writer.u32(to_u32(relocation.offset)?)?;
        writer.u32(to_u32(
            1usize
                .checked_add(index)
                .ok_or(ObjectError::OffsetOverflow)?,
        )?)?;
        writer.u16(4)?;
    }

    coff_symbol_name(&mut writer, symbol, 4)?;
    writer.u32(0)?;
    writer.i16(1)?;
    writer.u16(0x20)?;
    writer.write(&[2, 0])?;
    let mut external_string_offset = 4usize
        .checked_add(symbol_string_bytes)
        .ok_or(ObjectError::OffsetOverflow)?;
    for relocation in relocations {
        coff_symbol_name(&mut writer, relocation.symbol, external_string_offset)?;
        writer.u32(0)?;
        writer.i16(0)?;
        writer.u16(match relocation.kind {
            X86_64PcRelativeRelocationKind::Branch => 0x20,
            X86_64PcRelativeRelocationKind::Data => 0,
        })?;
        writer.write(&[2, 0])?;
        if relocation.symbol.len() > 8 {
            external_string_offset = external_string_offset
                .checked_add(relocation.symbol.len())
                .and_then(|offset| offset.checked_add(1))
                .ok_or(ObjectError::OffsetOverflow)?;
        }
    }
    writer.u32(to_u32(string_table_size)?)?;
    if symbol_long {
        writer.write(symbol.as_bytes())?;
        writer.write(&[0])?;
    }
    for relocation in relocations {
        if relocation.symbol.len() > 8 {
            writer.write(relocation.symbol.as_bytes())?;
            writer.write(&[0])?;
        }
    }
    Ok(writer.finish())
}

pub fn emit_x86_64_coff_with_readonly_data<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
>(
    symbol: &str,
    code: &MachineCode<MAX_CODE_BYTES>,
    data: &[u8],
    relocations: &[X86_64ReadonlyRelocation],
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, ObjectError> {
    validate_symbol(symbol)?;
    validate_readonly_relocations(code, data, relocations)?;
    let text_offset = COFF_HEADER_BYTES + COFF_SECTION_HEADER_BYTES * 2;
    let relocation_offset = text_offset
        .checked_add(code.len())
        .ok_or(ObjectError::OffsetOverflow)?;
    let data_offset = relocation_offset
        .checked_add(
            10usize
                .checked_mul(relocations.len())
                .ok_or(ObjectError::OffsetOverflow)?,
        )
        .ok_or(ObjectError::OffsetOverflow)?;
    let symbol_offset = data_offset
        .checked_add(data.len())
        .ok_or(ObjectError::OffsetOverflow)?;
    let symbol_long = symbol.len() > 8;
    let string_table_size = 4usize
        .checked_add(if symbol_long {
            symbol
                .len()
                .checked_add(1)
                .ok_or(ObjectError::OffsetOverflow)?
        } else {
            0
        })
        .ok_or(ObjectError::OffsetOverflow)?;
    let mut writer = Writer::new();

    writer.u16(0x8664)?;
    writer.u16(2)?;
    writer.u32(0)?;
    writer.u32(to_u32(symbol_offset)?)?;
    writer.u32(2)?;
    writer.u16(0)?;
    writer.u16(0)?;

    writer.write(b".text\0\0\0")?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(to_u32(code.len())?)?;
    writer.u32(to_u32(text_offset)?)?;
    writer.u32(to_u32(relocation_offset)?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(relocations.len()).map_err(|_| ObjectError::OffsetOverflow)?)?;
    writer.u16(0)?;
    writer.u32(0x6000_0020)?;

    writer.write(b".rdata\0\0")?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(to_u32(data.len())?)?;
    writer.u32(to_u32(data_offset)?)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u32(0x4000_0040)?;

    writer.write(code.bytes())?;
    for relocation in relocations {
        writer.patch_i32(
            text_offset
                .checked_add(relocation.offset)
                .ok_or(ObjectError::OffsetOverflow)?,
            i32::try_from(relocation.data_offset).map_err(|_| ObjectError::OffsetOverflow)?,
        )?;
    }
    for relocation in relocations {
        writer.u32(to_u32(relocation.offset)?)?;
        writer.u32(1)?;
        writer.u16(4)?;
    }
    writer.write(data)?;

    coff_symbol_name(&mut writer, symbol, 4)?;
    writer.u32(0)?;
    writer.i16(1)?;
    writer.u16(0x20)?;
    writer.write(&[2, 0])?;
    writer.write(b".rdata\0\0")?;
    writer.u32(0)?;
    writer.i16(2)?;
    writer.u16(0)?;
    writer.write(&[3, 0])?;
    writer.u32(to_u32(string_table_size)?)?;
    if symbol_long {
        writer.write(symbol.as_bytes())?;
        writer.write(&[0])?;
    }
    Ok(writer.finish())
}

fn coff_symbol_name<const MAX_BYTES: usize>(
    writer: &mut Writer<MAX_BYTES>,
    symbol: &str,
    string_offset: usize,
) -> Result<(), ObjectError> {
    if symbol.len() <= 8 {
        writer.write(symbol.as_bytes())?;
        writer.zeros(8 - symbol.len())
    } else {
        writer.u32(0)?;
        writer.u32(to_u32(string_offset)?)
    }
}

fn to_u32(value: usize) -> Result<u32, ObjectError> {
    u32::try_from(value).map_err(|_| ObjectError::OffsetOverflow)
}

fn to_u64(value: usize) -> Result<u64, ObjectError> {
    u64::try_from(value).map_err(|_| ObjectError::OffsetOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Item, NoConstants, Parser, compile_x86_64_constant_function};

    fn code() -> MachineCode<16> {
        let module = Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }")
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        compile_x86_64_constant_function::<_, 16, 2, 8>(&function, &NoConstants).unwrap()
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn emits_structurally_complete_elf64_relocatable_object() {
        let code = code();
        let object = emit_elf64_x86_64::<512, 16>("answer", &code).unwrap();
        let bytes = object.bytes();
        assert_eq!(&bytes[..9], b"\x7fELF\x02\x01\x01\x00\x00");
        assert_eq!(u16_at(bytes, 16), 1);
        assert_eq!(u16_at(bytes, 18), 62);
        assert_eq!(u16_at(bytes, 60), 5);
        assert_eq!(u16_at(bytes, 62), 4);
        assert_eq!(&bytes[64..75], code.bytes());
        let sections = u64_at(bytes, 40) as usize;
        assert_eq!(sections + 5 * ELF_SECTION_HEADER_BYTES, object.len());
        assert_eq!(u32_at(bytes, sections + ELF_SECTION_HEADER_BYTES), 1);
        assert_eq!(u64_at(bytes, sections + ELF_SECTION_HEADER_BYTES + 32), 11);
    }

    #[test]
    fn emits_coff_with_short_and_long_external_symbols() {
        let code = code();
        let short = emit_x86_64_coff::<256, 16>("answer", &code).unwrap();
        let bytes = short.bytes();
        assert_eq!(u16_at(bytes, 0), 0x8664);
        assert_eq!(u16_at(bytes, 2), 1);
        assert_eq!(u32_at(bytes, 8), 71);
        assert_eq!(&bytes[60..71], code.bytes());
        assert_eq!(&bytes[71..77], b"answer");
        assert_eq!(u32_at(bytes, 89), 4);

        let long = emit_x86_64_coff::<256, 16>("answer_to_everything", &code).unwrap();
        let bytes = long.bytes();
        assert_eq!(u32_at(bytes, 71), 0);
        assert_eq!(u32_at(bytes, 75), 4);
        assert_eq!(u32_at(bytes, 89), 25);
        assert_eq!(&bytes[93..113], b"answer_to_everything");
        assert_eq!(bytes[113], 0);
    }

    #[test]
    fn emits_checked_pc_relative_relocations_for_elf_and_coff() {
        let code = code();
        let relocation = X86_64PcRelativeRelocation {
            offset: 1,
            symbol: "external_target",
            kind: X86_64PcRelativeRelocationKind::Branch,
        };
        let elf =
            emit_elf64_x86_64_with_relocation::<768, 16>("answer", &code, relocation).unwrap();
        let bytes = elf.bytes();
        assert_eq!(u16_at(bytes, 60), 6);
        assert_eq!(u16_at(bytes, 62), 5);
        let sections = u64_at(bytes, 40) as usize;
        let rela = sections + 2 * ELF_SECTION_HEADER_BYTES;
        assert_eq!(u32_at(bytes, rela + 4), 4);
        assert_eq!(u32_at(bytes, rela + 40), 3);
        assert_eq!(u32_at(bytes, rela + 44), 1);
        let entries = u64_at(bytes, rela + 24) as usize;
        assert_eq!(u64_at(bytes, entries), 1);
        assert_eq!(u64_at(bytes, entries + 8), (2u64 << 32) | 4);
        assert_eq!(u64_at(bytes, entries + 16), (-4i64) as u64);

        let coff =
            emit_x86_64_coff_with_relocation::<384, 16>("answer", &code, relocation).unwrap();
        let bytes = coff.bytes();
        assert_eq!(u32_at(bytes, 44), 71);
        assert_eq!(u16_at(bytes, 52), 1);
        assert_eq!(u32_at(bytes, 71), 1);
        assert_eq!(u32_at(bytes, 75), 1);
        assert_eq!(u16_at(bytes, 79), 4);
        assert_eq!(u32_at(bytes, 8), 81);
        assert_eq!(u32_at(bytes, 12), 2);
        assert_eq!(i16::from_le_bytes(bytes[107..109].try_into().unwrap()), 0);
        assert_eq!(&bytes[121..136], b"external_target");

        let data = X86_64PcRelativeRelocation {
            kind: X86_64PcRelativeRelocationKind::Data,
            ..relocation
        };
        let elf = emit_elf64_x86_64_with_relocation::<768, 16>("answer", &code, data).unwrap();
        let bytes = elf.bytes();
        let sections = u64_at(bytes, 40) as usize;
        let rela = sections + 2 * ELF_SECTION_HEADER_BYTES;
        let entries = u64_at(bytes, rela + 24) as usize;
        assert_eq!(u64_at(bytes, entries + 8), (2u64 << 32) | 2);

        let coff = emit_x86_64_coff_with_relocation::<384, 16>("answer", &code, data).unwrap();
        assert_eq!(u16_at(coff.bytes(), 79), 4);
    }

    #[test]
    fn emits_bounded_mixed_relocation_collections() {
        let code = code();
        let relocations = [
            X86_64PcRelativeRelocation {
                offset: 0,
                symbol: "shared_external",
                kind: X86_64PcRelativeRelocationKind::Data,
            },
            X86_64PcRelativeRelocation {
                offset: 4,
                symbol: "branch_target",
                kind: X86_64PcRelativeRelocationKind::Branch,
            },
            X86_64PcRelativeRelocation {
                offset: 7,
                symbol: "shared_external",
                kind: X86_64PcRelativeRelocationKind::Data,
            },
        ];
        let elf =
            emit_elf64_x86_64_with_relocations::<1024, 16>("answer", &code, &relocations).unwrap();
        let bytes = elf.bytes();
        let sections = u64_at(bytes, 40) as usize;
        let rela = sections + 2 * ELF_SECTION_HEADER_BYTES;
        assert_eq!(u64_at(bytes, rela + 32), 72);
        let entries = u64_at(bytes, rela + 24) as usize;
        assert_eq!(u64_at(bytes, entries + 8), (2u64 << 32) | 2);
        assert_eq!(u64_at(bytes, entries + 24 + 8), (3u64 << 32) | 4);
        assert_eq!(u64_at(bytes, entries + 48 + 8), (4u64 << 32) | 2);
        let symbols = sections + 3 * ELF_SECTION_HEADER_BYTES;
        assert_eq!(u64_at(bytes, symbols + 32), ELF_SYMBOL_BYTES as u64 * 5);

        let coff =
            emit_x86_64_coff_with_relocations::<768, 16>("answer", &code, &relocations).unwrap();
        let bytes = coff.bytes();
        assert_eq!(u16_at(bytes, 52), 3);
        assert_eq!(u32_at(bytes, 12), 4);
        let relocation_offset = u32_at(bytes, 44) as usize;
        assert_eq!(u32_at(bytes, relocation_offset + 4), 1);
        assert_eq!(u32_at(bytes, relocation_offset + 10 + 4), 2);
        assert_eq!(u32_at(bytes, relocation_offset + 20 + 4), 3);
        let symbol_offset = u32_at(bytes, 8) as usize;
        assert_eq!(u16_at(bytes, symbol_offset + 18 + 14), 0);
        assert_eq!(u16_at(bytes, symbol_offset + 36 + 14), 0x20);
        assert_eq!(u16_at(bytes, symbol_offset + 54 + 14), 0);

        let too_many = [relocations[0]; MAX_X86_64_RELOCATIONS + 1];
        assert_eq!(
            emit_elf64_x86_64_with_relocations::<2048, 16>("answer", &code, &too_many),
            Err(ObjectError::TooManyRelocations)
        );
        assert_eq!(
            emit_x86_64_coff_with_relocations::<2048, 16>("answer", &code, &too_many),
            Err(ObjectError::TooManyRelocations)
        );
    }

    #[test]
    fn emits_bounded_internal_readonly_data_relocations() {
        let code = code();
        let data = b"leftRIGHT";
        let relocations = [
            X86_64ReadonlyRelocation {
                offset: 1,
                data_offset: 0,
            },
            X86_64ReadonlyRelocation {
                offset: 5,
                data_offset: 4,
            },
        ];

        let elf =
            emit_elf64_x86_64_with_readonly_data::<1024, 16>("answer", &code, data, &relocations)
                .unwrap();
        let bytes = elf.bytes();
        assert_eq!(u16_at(bytes, 60), 7);
        assert_eq!(u16_at(bytes, 62), 6);
        let sections = u64_at(bytes, 40) as usize;
        let rela = sections + 2 * ELF_SECTION_HEADER_BYTES;
        let rodata = sections + 3 * ELF_SECTION_HEADER_BYTES;
        let entries = u64_at(bytes, rela + 24) as usize;
        assert_eq!(u64_at(bytes, entries + 8), (1u64 << 32) | 2);
        assert_eq!(u64_at(bytes, entries + 16), (-4i64) as u64);
        assert_eq!(u64_at(bytes, entries + 24 + 16), 0);
        let readonly_offset = u64_at(bytes, rodata + 24) as usize;
        assert_eq!(&bytes[readonly_offset..readonly_offset + data.len()], data);
        assert_eq!(u64_at(bytes, rodata + 8), 2);

        let coff =
            emit_x86_64_coff_with_readonly_data::<512, 16>("answer", &code, data, &relocations)
                .unwrap();
        let bytes = coff.bytes();
        assert_eq!(u16_at(bytes, 2), 2);
        assert_eq!(&bytes[60..68], b".rdata\0\0");
        let text_offset = u32_at(bytes, 40) as usize;
        let coff_relocations = u32_at(bytes, 44) as usize;
        let readonly_offset = u32_at(bytes, 80) as usize;
        assert_eq!(u32_at(bytes, text_offset + 1), 0);
        assert_eq!(u32_at(bytes, text_offset + 5), 4);
        assert_eq!(u32_at(bytes, coff_relocations + 4), 1);
        assert_eq!(u32_at(bytes, coff_relocations + 10 + 4), 1);
        assert_eq!(&bytes[readonly_offset..readonly_offset + data.len()], data);
        assert_eq!(u32_at(bytes, 12), 2);

        let invalid = X86_64ReadonlyRelocation {
            offset: 1,
            data_offset: data.len() + 1,
        };
        assert_eq!(
            emit_elf64_x86_64_with_readonly_data::<1024, 16>("answer", &code, data, &[invalid]),
            Err(ObjectError::InvalidReadonlyDataOffset)
        );
    }

    #[test]
    fn object_emission_is_deterministic_and_bounded() {
        let code = code();
        let first = emit_elf64_x86_64::<512, 16>("answer", &code).unwrap();
        let second = emit_elf64_x86_64::<512, 16>("answer", &code).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            emit_elf64_x86_64::<64, 16>("answer", &code),
            Err(ObjectError::OutputTooSmall)
        );
        assert_eq!(
            emit_x86_64_coff::<32, 16>("answer", &code),
            Err(ObjectError::OutputTooSmall)
        );
    }

    #[test]
    fn rejects_names_that_cannot_enter_a_string_table() {
        let code = code();
        assert_eq!(
            emit_elf64_x86_64::<512, 16>("", &code),
            Err(ObjectError::EmptySymbol)
        );
        assert_eq!(
            emit_x86_64_coff::<256, 16>("bad\0name", &code),
            Err(ObjectError::SymbolContainsNul)
        );
        let invalid = X86_64PcRelativeRelocation {
            offset: code.len() - 3,
            symbol: "external_target",
            kind: X86_64PcRelativeRelocationKind::Branch,
        };
        assert_eq!(
            emit_elf64_x86_64_with_relocation::<768, 16>("answer", &code, invalid),
            Err(ObjectError::InvalidRelocationOffset)
        );
        assert_eq!(
            emit_x86_64_coff_with_relocation::<384, 16>("answer", &code, invalid),
            Err(ObjectError::InvalidRelocationOffset)
        );
    }
}
