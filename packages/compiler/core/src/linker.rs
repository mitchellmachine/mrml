//! Bounded, deterministic x86-64 static-link planning and relocation.
//!
//! The passes deliberately have no shared mutable work between inputs until the
//! final copy/relocation pass. A hosted driver can therefore parallelize input
//! validation and relocation scanning later without changing link semantics.

pub const MAX_LINK_INPUTS: usize = 32;
pub const MAX_LINK_RELOCATIONS: usize = 256;
pub const MAX_ARCHIVE_MEMBERS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkerError {
    EmptyInput,
    EmptySymbol,
    SymbolContainsNul,
    TooManyInputs,
    TooManyRelocations,
    DuplicateSymbol,
    UndefinedSymbol,
    InvalidRelocationOffset,
    OffsetOverflow,
    RelocationOverflow,
    OutputTooSmall,
    InvalidCoff,
    UnsupportedCoff,
    InvalidElf,
    UnsupportedElf,
    InvalidArchive,
    TooManyArchiveMembers,
}

impl core::fmt::Display for LinkerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::EmptyInput => "link input set is empty",
            Self::EmptySymbol => "link symbol is empty",
            Self::SymbolContainsNul => "link symbol contains NUL",
            Self::TooManyInputs => "link input capacity exceeded",
            Self::TooManyRelocations => "link relocation capacity exceeded",
            Self::DuplicateSymbol => "duplicate link symbol",
            Self::UndefinedSymbol => "undefined link symbol",
            Self::InvalidRelocationOffset => "invalid link relocation offset",
            Self::OffsetOverflow => "link offset arithmetic overflow",
            Self::RelocationOverflow => "link relocation displacement overflow",
            Self::OutputTooSmall => "link output capacity is too small",
            Self::InvalidCoff => "invalid bounded COFF input",
            Self::UnsupportedCoff => "unsupported COFF feature",
            Self::InvalidElf => "invalid bounded ELF64 input",
            Self::UnsupportedElf => "unsupported ELF64 feature",
            Self::InvalidArchive => "invalid Unix archive input",
            Self::TooManyArchiveMembers => "archive member capacity exceeded",
        };
        formatter.write_str(message)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveMember<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveMembers<'a> {
    members: [ArchiveMember<'a>; MAX_ARCHIVE_MEMBERS],
    length: usize,
}

impl<'a> ArchiveMembers<'a> {
    pub fn members(&self) -> &[ArchiveMember<'a>] {
        &self.members[..self.length]
    }
}

/// Decodes ordinary Unix `ar`, GNU long-name, and BSD extended-name members.
/// Archive symbol indexes are metadata and are skipped; member selection remains
/// a separate linker pass.
pub fn decode_unix_archive(archive: &[u8]) -> Result<ArchiveMembers<'_>, LinkerError> {
    if archive.get(..8) != Some(b"!<arch>\n") {
        return Err(LinkerError::InvalidArchive);
    }
    let empty = ArchiveMember {
        name: "",
        bytes: &archive[0..0],
    };
    let mut decoded = ArchiveMembers {
        members: [empty; MAX_ARCHIVE_MEMBERS],
        length: 0,
    };
    let mut string_table = None;
    let mut cursor = 8usize;
    while cursor < archive.len() {
        let header_end = cursor.checked_add(60).ok_or(LinkerError::OffsetOverflow)?;
        let header = archive
            .get(cursor..header_end)
            .ok_or(LinkerError::InvalidArchive)?;
        if header.get(58..60) != Some(b"`\n") {
            return Err(LinkerError::InvalidArchive);
        }
        let stored_size =
            parse_archive_decimal(header.get(48..58).ok_or(LinkerError::InvalidArchive)?)?;
        let stored_end = header_end
            .checked_add(stored_size)
            .ok_or(LinkerError::OffsetOverflow)?;
        let stored = archive
            .get(header_end..stored_end)
            .ok_or(LinkerError::InvalidArchive)?;
        let raw_name = trim_archive_field(header.get(..16).ok_or(LinkerError::InvalidArchive)?)?;

        if raw_name == "//" {
            string_table = Some(stored);
        } else if raw_name != "/" && raw_name != "/SYM64/" && !raw_name.starts_with("__.SYMDEF") {
            let (name, bytes) = decode_archive_member(raw_name, stored, string_table)?;
            if decoded.length == MAX_ARCHIVE_MEMBERS {
                return Err(LinkerError::TooManyArchiveMembers);
            }
            decoded.members[decoded.length] = ArchiveMember { name, bytes };
            decoded.length += 1;
        }

        cursor = stored_end
            .checked_add(stored_size & 1)
            .ok_or(LinkerError::OffsetOverflow)?;
        if cursor > archive.len() {
            return Err(LinkerError::InvalidArchive);
        }
    }
    Ok(decoded)
}

fn decode_archive_member<'a>(
    raw_name: &'a str,
    stored: &'a [u8],
    string_table: Option<&'a [u8]>,
) -> Result<(&'a str, &'a [u8]), LinkerError> {
    if let Some(length) = raw_name.strip_prefix("#1/") {
        let name_length = parse_archive_usize(length.as_bytes())?;
        let name_bytes = stored
            .get(..name_length)
            .ok_or(LinkerError::InvalidArchive)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| LinkerError::InvalidArchive)?;
        return Ok((name, &stored[name_length..]));
    }
    if let Some(offset) = raw_name.strip_prefix('/') {
        let offset = parse_archive_usize(offset.as_bytes())?;
        let strings = string_table.ok_or(LinkerError::InvalidArchive)?;
        let suffix = strings.get(offset..).ok_or(LinkerError::InvalidArchive)?;
        let end = suffix
            .windows(2)
            .position(|bytes| bytes == b"/\n")
            .ok_or(LinkerError::InvalidArchive)?;
        let name = core::str::from_utf8(&suffix[..end]).map_err(|_| LinkerError::InvalidArchive)?;
        return Ok((name, stored));
    }
    Ok((raw_name.strip_suffix('/').unwrap_or(raw_name), stored))
}

fn trim_archive_field(field: &[u8]) -> Result<&str, LinkerError> {
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |i| i + 1);
    core::str::from_utf8(&field[..end]).map_err(|_| LinkerError::InvalidArchive)
}

fn parse_archive_decimal(field: &[u8]) -> Result<usize, LinkerError> {
    let end = field
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(field.len());
    parse_archive_usize(&field[..end])
}

fn parse_archive_usize(digits: &[u8]) -> Result<usize, LinkerError> {
    if digits.is_empty() || digits.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(LinkerError::InvalidArchive);
    }
    let mut value = 0usize;
    for digit in digits {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(*digit - b'0')))
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkRelocation<'a> {
    /// Offset of the four-byte x86-64 PC-relative field in this input's text.
    pub offset: usize,
    pub target: LinkRelocationTarget<'a>,
    /// Explicit object-format addend. A call/jump rel32 normally uses `-4`.
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRelocationTarget<'a> {
    Symbol(&'a str),
    ReadonlyData(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInput<'data, 'relocations> {
    pub symbol: &'data str,
    pub text: &'data [u8],
    pub readonly_data: &'data [u8],
    pub relocations: &'relocations [LinkRelocation<'data>],
}

/// Decodes the bounded x86-64 COFF subset emitted by `mrml-rustc` into the
/// format-neutral static-link input. The caller owns relocation storage so the
/// dependency-free compiler core never allocates.
pub fn decode_x86_64_coff<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<LinkInput<'data, 'relocations>, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 2 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let symbol_offset =
        usize::try_from(read_u32(object, 8)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbol_count =
        usize::try_from(read_u32(object, 12)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbols_end = symbol_offset
        .checked_add(
            symbol_count
                .checked_mul(18)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    object
        .get(symbol_offset..symbols_end)
        .ok_or(LinkerError::InvalidCoff)?;
    let string_size =
        usize::try_from(read_u32(object, symbols_end)?).map_err(|_| LinkerError::OffsetOverflow)?;
    if string_size < 4 {
        return Err(LinkerError::InvalidCoff);
    }
    let strings_end = symbols_end
        .checked_add(string_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    object
        .get(symbols_end..strings_end)
        .ok_or(LinkerError::InvalidCoff)?;

    let mut text = None;
    let mut readonly_data = &object[0..0];
    let mut relocation_table = (0usize, 0usize);
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let name = object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let offset = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let contents = object
            .get(
                offset
                    ..offset
                        .checked_add(size)
                        .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::InvalidCoff)?;
        if name == b".text\0\0\0" {
            if text.replace(contents).is_some() {
                return Err(LinkerError::InvalidCoff);
            }
            relocation_table = (
                usize::try_from(read_u32(object, header + 24)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
                usize::from(read_u16(object, header + 32)?),
            );
        } else if name == b".rdata\0\0" {
            readonly_data = contents;
        } else {
            return Err(LinkerError::UnsupportedCoff);
        }
    }
    let text = text.ok_or(LinkerError::InvalidCoff)?;

    let mut defined_symbol = None;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let offset = symbol_offset + symbol_index * 18;
        let section = read_i16(object, offset + 12)?;
        let auxiliary = usize::from(*object.get(offset + 17).ok_or(LinkerError::InvalidCoff)?);
        if section == 1 {
            let name = coff_symbol_name(object, offset, symbols_end, string_size)?;
            if defined_symbol.replace(name).is_some() || read_u32(object, offset + 8)? != 0 {
                return Err(LinkerError::UnsupportedCoff);
            }
        } else if section != 0 && section != 2 {
            return Err(LinkerError::UnsupportedCoff);
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let symbol = defined_symbol.ok_or(LinkerError::InvalidCoff)?;

    if relocation_table.1 > relocation_storage.len() {
        return Err(LinkerError::TooManyRelocations);
    }
    for index in 0..relocation_table.1 {
        let offset = relocation_table
            .0
            .checked_add(index.checked_mul(10).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let field_offset =
            usize::try_from(read_u32(object, offset)?).map_err(|_| LinkerError::OffsetOverflow)?;
        let target_index = usize::try_from(read_u32(object, offset + 4)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if target_index >= symbol_count || read_u16(object, offset + 8)? != 4 {
            return Err(LinkerError::UnsupportedCoff);
        }
        let target_offset = symbol_offset
            .checked_add(
                target_index
                    .checked_mul(18)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        let target_section = read_i16(object, target_offset + 12)?;
        let field_addend = read_i32(text, field_offset)?;
        let (target, addend) = if target_section == 0 {
            (
                LinkRelocationTarget::Symbol(coff_symbol_name(
                    object,
                    target_offset,
                    symbols_end,
                    string_size,
                )?),
                i64::from(field_addend) - 4,
            )
        } else if target_section == 2 && read_u32(object, target_offset + 8)? == 0 {
            let data_offset =
                usize::try_from(field_addend).map_err(|_| LinkerError::InvalidRelocationOffset)?;
            if data_offset > readonly_data.len() {
                return Err(LinkerError::InvalidRelocationOffset);
            }
            (LinkRelocationTarget::ReadonlyData(data_offset), -4)
        } else {
            return Err(LinkerError::UnsupportedCoff);
        };
        relocation_storage[index] = LinkRelocation {
            offset: field_offset,
            target,
            addend,
        };
    }

    Ok(LinkInput {
        symbol,
        text,
        readonly_data,
        relocations: &relocation_storage[..relocation_table.1],
    })
}

/// Decodes the exact bounded ELF64 relocatable subset emitted by `mrml-rustc`.
pub fn decode_x86_64_elf<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<LinkInput<'data, 'relocations>, LinkerError> {
    if object.get(..9) != Some(b"\x7fELF\x02\x01\x01\x00\x00")
        || read_u16_elf(object, 16)? != 1
        || read_u16_elf(object, 18)? != 62
        || read_u32_elf(object, 20)? != 1
    {
        return Err(LinkerError::UnsupportedElf);
    }
    if read_u16_elf(object, 52)? != 64 || read_u16_elf(object, 58)? != 64 {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let section_names_index = usize::from(read_u16_elf(object, 62)?);
    if !(5..=7).contains(&section_count) || section_names_index >= section_count {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_bytes = section_count
        .checked_mul(64)
        .ok_or(LinkerError::OffsetOverflow)?;
    object
        .get(
            section_offset
                ..section_offset
                    .checked_add(section_bytes)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidElf)?;
    let section_names =
        elf_section_contents(object, section_offset, section_count, section_names_index)?;

    let mut text_index = None;
    let mut readonly_index = None;
    let mut relocations_index = None;
    let mut symbols_index = None;
    let mut strings_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        let name_offset = usize::try_from(read_u32_elf(object, header)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let name = elf_string(section_names, name_offset)?;
        match name {
            ".text" if text_index.replace(index).is_none() => {}
            ".rodata" if readonly_index.replace(index).is_none() => {}
            ".rela.text" if relocations_index.replace(index).is_none() => {}
            ".symtab" if symbols_index.replace(index).is_none() => {}
            ".strtab" if strings_index.replace(index).is_none() => {}
            ".shstrtab" if index == section_names_index => {}
            _ => return Err(LinkerError::UnsupportedElf),
        }
    }
    let text_index = text_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let strings_index = strings_index.ok_or(LinkerError::InvalidElf)?;
    let text = elf_section_contents(object, section_offset, section_count, text_index)?;
    let readonly_data = match readonly_index {
        Some(index) => elf_section_contents(object, section_offset, section_count, index)?,
        None => &object[0..0],
    };
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;

    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    if read_u32_elf(object, symbols_header + 4)? != 2
        || read_u64_elf(object, symbols_header + 56)? != 24
        || usize::try_from(read_u32_elf(object, symbols_header + 40)?)
            .map_err(|_| LinkerError::OffsetOverflow)?
            != strings_index
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    if symbols.len() % 24 != 0 || symbols.len() < 48 {
        return Err(LinkerError::InvalidElf);
    }
    let symbol_count = symbols.len() / 24;
    let mut defined_symbol = None;
    for index in 1..symbol_count {
        let offset = index * 24;
        let section = usize::from(read_u16_elf(symbols, offset + 6)?);
        if section == text_index {
            if read_u64_elf(symbols, offset + 8)? != 0 {
                return Err(LinkerError::UnsupportedElf);
            }
            let name = elf_string(
                strings,
                usize::try_from(read_u32_elf(symbols, offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
            if defined_symbol.replace(name).is_some() {
                return Err(LinkerError::UnsupportedElf);
            }
        } else if section != 0 && Some(section) != readonly_index {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let symbol = defined_symbol.ok_or(LinkerError::InvalidElf)?;

    let relocation_count = if let Some(index) = relocations_index {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? != 4
            || read_u64_elf(object, header + 56)? != 24
            || usize::try_from(read_u32_elf(object, header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != symbols_index
            || usize::try_from(read_u32_elf(object, header + 44)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != text_index
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        if records.len() % 24 != 0 || records.len() / 24 > relocation_storage.len() {
            return Err(LinkerError::TooManyRelocations);
        }
        for (record_index, record) in records.chunks_exact(24).enumerate() {
            let offset = to_usize_elf(read_u64_elf(record, 0)?)?;
            offset
                .checked_add(4)
                .filter(|end| *end <= text.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            let info = read_u64_elf(record, 8)?;
            let relocation_type =
                u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)?;
            if relocation_type != 2 && relocation_type != 4 {
                return Err(LinkerError::UnsupportedElf);
            }
            let target_index =
                usize::try_from(info >> 32).map_err(|_| LinkerError::OffsetOverflow)?;
            if target_index >= symbol_count {
                return Err(LinkerError::InvalidElf);
            }
            let target_offset = target_index * 24;
            let target_section = usize::from(read_u16_elf(symbols, target_offset + 6)?);
            let encoded_addend = read_i64_elf(record, 16)?;
            let (target, addend) = if target_section == 0 {
                (
                    LinkRelocationTarget::Symbol(elf_string(
                        strings,
                        usize::try_from(read_u32_elf(symbols, target_offset)?)
                            .map_err(|_| LinkerError::OffsetOverflow)?,
                    )?),
                    encoded_addend,
                )
            } else if Some(target_section) == readonly_index {
                let data_offset = usize::try_from(
                    encoded_addend
                        .checked_add(4)
                        .ok_or(LinkerError::OffsetOverflow)?,
                )
                .map_err(|_| LinkerError::InvalidRelocationOffset)?;
                if data_offset > readonly_data.len() {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                (LinkRelocationTarget::ReadonlyData(data_offset), -4)
            } else {
                return Err(LinkerError::UnsupportedElf);
            };
            relocation_storage[record_index] = LinkRelocation {
                offset,
                target,
                addend,
            };
        }
        records.len() / 24
    } else {
        0
    };
    Ok(LinkInput {
        symbol,
        text,
        readonly_data,
        relocations: &relocation_storage[..relocation_count],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
    text_length: usize,
    readonly_offset: usize,
    entry_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
}

impl<const MAX_BYTES: usize> ElfImage<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl<const MAX_BYTES: usize> PeImage<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl<const MAX_BYTES: usize> LinkedImage<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub const fn readonly_offset(&self) -> usize {
        self.readonly_offset
    }

    pub const fn entry_offset(&self) -> usize {
        self.entry_offset
    }
}

#[derive(Clone, Copy)]
struct InputLayout {
    text: usize,
    readonly: usize,
}

/// Links already-decoded MRML x86-64 fragments into one position-independent
/// image. Input order is significant and makes the result reproducible.
pub fn link_x86_64_static<const MAX_BYTES: usize>(
    inputs: &[LinkInput<'_, '_>],
    entry_symbol: &str,
) -> Result<LinkedImage<MAX_BYTES>, LinkerError> {
    link_x86_64_static_aligned(inputs, entry_symbol, 16)
}

/// Links MRML COFF fragments and writes a deterministic, import-free PE32+
/// executable with separate RX code and read-only NX data sections.
pub fn link_x86_64_pe<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_>],
    entry_symbol: &str,
) -> Result<PeImage<MAX_IMAGE_BYTES>, LinkerError> {
    const FILE_ALIGNMENT: usize = 0x200;
    const SECTION_ALIGNMENT: usize = 0x1000;
    const HEADERS: usize = 0x200;
    const TEXT_RVA: usize = 0x1000;

    let linked =
        link_x86_64_static_aligned::<MAX_LINKED_BYTES>(inputs, entry_symbol, SECTION_ALIGNMENT)?;
    let text_size = linked.text_length;
    let readonly_size = linked.length - linked.readonly_offset;
    let text_raw_size = align(text_size, FILE_ALIGNMENT)?;
    let readonly_raw_size = align(readonly_size, FILE_ALIGNMENT)?;
    let readonly_raw = HEADERS
        .checked_add(text_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    let length = if readonly_size == 0 {
        readonly_raw
    } else {
        readonly_raw
            .checked_add(readonly_raw_size)
            .ok_or(LinkerError::OffsetOverflow)?
    };
    if length > MAX_IMAGE_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    let readonly_rva = TEXT_RVA
        .checked_add(linked.readonly_offset)
        .ok_or(LinkerError::OffsetOverflow)?;
    let size_of_image = if readonly_size == 0 {
        align(
            TEXT_RVA
                .checked_add(text_size)
                .ok_or(LinkerError::OffsetOverflow)?,
            SECTION_ALIGNMENT,
        )?
    } else {
        align(
            readonly_rva
                .checked_add(readonly_size)
                .ok_or(LinkerError::OffsetOverflow)?,
            SECTION_ALIGNMENT,
        )?
    };

    let mut bytes = [0u8; MAX_IMAGE_BYTES];
    bytes[0..2].copy_from_slice(b"MZ");
    patch_u32(&mut bytes, 0x3c, 0x80)?;
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    patch_u16(&mut bytes, 0x84, 0x8664)?;
    patch_u16(&mut bytes, 0x86, if readonly_size == 0 { 1 } else { 2 })?;
    patch_u16(&mut bytes, 0x94, 240)?;
    patch_u16(&mut bytes, 0x96, 0x0023)?;

    let optional = 0x98;
    patch_u16(&mut bytes, optional, 0x20b)?;
    patch_u32(&mut bytes, optional + 4, to_u32_link(text_raw_size)?)?;
    patch_u32(&mut bytes, optional + 8, to_u32_link(readonly_raw_size)?)?;
    patch_u32(
        &mut bytes,
        optional + 16,
        to_u32_link(TEXT_RVA + linked.entry_offset)?,
    )?;
    patch_u32(&mut bytes, optional + 20, to_u32_link(TEXT_RVA)?)?;
    patch_u64(&mut bytes, optional + 24, 0x0000_0001_4000_0000)?;
    patch_u32(&mut bytes, optional + 32, to_u32_link(SECTION_ALIGNMENT)?)?;
    patch_u32(&mut bytes, optional + 36, to_u32_link(FILE_ALIGNMENT)?)?;
    patch_u16(&mut bytes, optional + 40, 6)?;
    patch_u16(&mut bytes, optional + 48, 6)?;
    patch_u32(&mut bytes, optional + 56, to_u32_link(size_of_image)?)?;
    patch_u32(&mut bytes, optional + 60, to_u32_link(HEADERS)?)?;
    patch_u16(&mut bytes, optional + 68, 3)?;
    patch_u16(&mut bytes, optional + 70, 0x8100)?;
    patch_u64(&mut bytes, optional + 72, 0x10_0000)?;
    patch_u64(&mut bytes, optional + 80, 0x1000)?;
    patch_u64(&mut bytes, optional + 88, 0x10_0000)?;
    patch_u64(&mut bytes, optional + 96, 0x1000)?;
    patch_u32(&mut bytes, optional + 108, 16)?;

    write_pe_section(
        &mut bytes,
        0x188,
        b".text\0\0\0",
        text_size,
        TEXT_RVA,
        text_raw_size,
        HEADERS,
        0x6000_0020,
    )?;
    if readonly_size != 0 {
        write_pe_section(
            &mut bytes,
            0x1b0,
            b".rdata\0\0",
            readonly_size,
            readonly_rva,
            readonly_raw_size,
            readonly_raw,
            0x4000_0040,
        )?;
    }
    copy_at(&mut bytes, HEADERS, &linked.bytes[..linked.text_length])?;
    if readonly_size != 0 {
        copy_at(
            &mut bytes,
            readonly_raw,
            &linked.bytes[linked.readonly_offset..linked.length],
        )?;
    }
    Ok(PeImage { bytes, length })
}

/// Links MRML fragments into a deterministic, fixed-address, import-free
/// x86-64 ELF executable with page-separated load permissions.
pub fn link_x86_64_elf_executable<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_>],
    entry_symbol: &str,
) -> Result<ElfImage<MAX_IMAGE_BYTES>, LinkerError> {
    const PAGE: usize = 0x1000;
    const IMAGE_BASE: usize = 0x40_0000;
    const TEXT_OFFSET: usize = 0x1000;

    let linked = link_x86_64_static_aligned::<MAX_LINKED_BYTES>(inputs, entry_symbol, PAGE)?;
    let readonly_size = linked.length - linked.readonly_offset;
    let readonly_offset = TEXT_OFFSET
        .checked_add(linked.readonly_offset)
        .ok_or(LinkerError::OffsetOverflow)?;
    let length = if readonly_size == 0 {
        TEXT_OFFSET
            .checked_add(linked.text_length)
            .ok_or(LinkerError::OffsetOverflow)?
    } else {
        readonly_offset
            .checked_add(readonly_size)
            .ok_or(LinkerError::OffsetOverflow)?
    };
    if length > MAX_IMAGE_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    let program_count = if readonly_size == 0 { 2 } else { 3 };
    let header_bytes = 64usize
        .checked_add(program_count * 56)
        .ok_or(LinkerError::OffsetOverflow)?;
    let mut bytes = [0u8; MAX_IMAGE_BYTES];
    bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    patch_u16(&mut bytes, 16, 2)?;
    patch_u16(&mut bytes, 18, 62)?;
    patch_u32(&mut bytes, 20, 1)?;
    patch_u64(
        &mut bytes,
        24,
        u64::try_from(
            IMAGE_BASE
                .checked_add(TEXT_OFFSET)
                .and_then(|value| value.checked_add(linked.entry_offset))
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u64(&mut bytes, 32, 64)?;
    patch_u16(&mut bytes, 52, 64)?;
    patch_u16(&mut bytes, 54, 56)?;
    patch_u16(&mut bytes, 56, program_count as u16)?;

    write_elf_load_segment(&mut bytes, 64, 4, 0, IMAGE_BASE, header_bytes, header_bytes)?;
    write_elf_load_segment(
        &mut bytes,
        120,
        5,
        TEXT_OFFSET,
        IMAGE_BASE + TEXT_OFFSET,
        linked.text_length,
        linked.text_length,
    )?;
    if readonly_size != 0 {
        write_elf_load_segment(
            &mut bytes,
            176,
            4,
            readonly_offset,
            IMAGE_BASE + readonly_offset,
            readonly_size,
            readonly_size,
        )?;
    }
    copy_at(&mut bytes, TEXT_OFFSET, &linked.bytes[..linked.text_length])?;
    if readonly_size != 0 {
        copy_at(
            &mut bytes,
            readonly_offset,
            &linked.bytes[linked.readonly_offset..linked.length],
        )?;
    }
    Ok(ElfImage { bytes, length })
}

fn write_elf_load_segment<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    flags: u32,
    file_offset: usize,
    virtual_address: usize,
    file_size: usize,
    memory_size: usize,
) -> Result<(), LinkerError> {
    patch_u32(output, offset, 1)?;
    patch_u32(output, offset + 4, flags)?;
    patch_u64(
        output,
        offset + 8,
        u64::try_from(file_offset).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    let address = u64::try_from(virtual_address).map_err(|_| LinkerError::OffsetOverflow)?;
    patch_u64(output, offset + 16, address)?;
    patch_u64(output, offset + 24, address)?;
    patch_u64(
        output,
        offset + 32,
        u64::try_from(file_size).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u64(
        output,
        offset + 40,
        u64::try_from(memory_size).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u64(output, offset + 48, 0x1000)
}

fn link_x86_64_static_aligned<const MAX_BYTES: usize>(
    inputs: &[LinkInput<'_, '_>],
    entry_symbol: &str,
    section_alignment: usize,
) -> Result<LinkedImage<MAX_BYTES>, LinkerError> {
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;

    // Pass 1: validate independent inputs and construct the global symbol set.
    let mut relocation_count = 0usize;
    for (index, input) in inputs.iter().enumerate() {
        validate_symbol(input.symbol)?;
        relocation_count = relocation_count
            .checked_add(input.relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if relocation_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for earlier in &inputs[..index] {
            if earlier.symbol == input.symbol {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        for relocation in input.relocations {
            match relocation.target {
                LinkRelocationTarget::Symbol(symbol) => validate_symbol(symbol)?,
                LinkRelocationTarget::ReadonlyData(offset)
                    if offset > input.readonly_data.len() =>
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                LinkRelocationTarget::ReadonlyData(_) => {}
            }
            relocation
                .offset
                .checked_add(4)
                .filter(|end| *end <= input.text.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
        }
    }

    // Pass 2: freeze layout before copying bytes, following a text-first,
    // read-only-data-second policy. The fixed arrays keep all bounds explicit.
    let mut layouts = [InputLayout {
        text: 0,
        readonly: 0,
    }; MAX_LINK_INPUTS];
    let mut cursor = 0usize;
    for (layout, input) in layouts.iter_mut().zip(inputs) {
        cursor = align(cursor, 16)?;
        layout.text = cursor;
        cursor = cursor
            .checked_add(input.text.len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let text_length = cursor;
    let readonly_offset = align(cursor, section_alignment)?;
    cursor = readonly_offset;
    for (layout, input) in layouts.iter_mut().zip(inputs) {
        cursor = align(cursor, 16)?;
        layout.readonly = cursor;
        cursor = cursor
            .checked_add(input.readonly_data.len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if cursor > MAX_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }

    let entry_offset = resolve_symbol(inputs, &layouts, entry_symbol)?;
    let mut output = [0u8; MAX_BYTES];

    // Pass 3: disjoint copies are independently executable once layout is fixed.
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        copy_at(&mut output, layout.text, input.text)?;
        copy_at(&mut output, layout.readonly, input.readonly_data)?;
    }

    // Pass 4: each relocation patches a disjoint field validated above.
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        for relocation in input.relocations {
            let place = layout
                .text
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = match relocation.target {
                LinkRelocationTarget::Symbol(symbol) => resolve_symbol(inputs, &layouts, symbol)?,
                LinkRelocationTarget::ReadonlyData(offset) => layout
                    .readonly
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
            };
            let displacement = i64::try_from(target)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(relocation.addend)
                .and_then(|value| value.checked_sub(i64::try_from(place).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement =
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?;
            output[place..place + 4].copy_from_slice(&displacement.to_le_bytes());
        }
    }

    Ok(LinkedImage {
        bytes: output,
        length: cursor,
        text_length,
        readonly_offset,
        entry_offset,
    })
}

fn write_pe_section<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    name: &[u8; 8],
    virtual_size: usize,
    virtual_address: usize,
    raw_size: usize,
    raw_offset: usize,
    characteristics: u32,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(name);
    patch_u32(output, offset + 8, to_u32_link(virtual_size)?)?;
    patch_u32(output, offset + 12, to_u32_link(virtual_address)?)?;
    patch_u32(output, offset + 16, to_u32_link(raw_size)?)?;
    patch_u32(output, offset + 20, to_u32_link(raw_offset)?)?;
    patch_u32(output, offset + 36, characteristics)
}

fn patch_u16<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    value: u16,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 2)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_u32<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    value: u32,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_u64<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    value: u64,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn to_u32_link(value: usize) -> Result<u32, LinkerError> {
    u32::try_from(value).map_err(|_| LinkerError::OffsetOverflow)
}

fn validate_symbol(symbol: &str) -> Result<(), LinkerError> {
    if symbol.is_empty() {
        Err(LinkerError::EmptySymbol)
    } else if symbol.as_bytes().contains(&0) {
        Err(LinkerError::SymbolContainsNul)
    } else {
        Ok(())
    }
}

fn resolve_symbol(
    inputs: &[LinkInput<'_, '_>],
    layouts: &[InputLayout; MAX_LINK_INPUTS],
    symbol: &str,
) -> Result<usize, LinkerError> {
    inputs
        .iter()
        .zip(layouts.iter())
        .find_map(|(input, layout)| (input.symbol == symbol).then_some(layout.text))
        .ok_or(LinkerError::UndefinedSymbol)
}

fn align(value: usize, alignment: usize) -> Result<usize, LinkerError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(LinkerError::OffsetOverflow)
}

fn copy_at<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    input: &[u8],
) -> Result<(), LinkerError> {
    let end = offset
        .checked_add(input.len())
        .ok_or(LinkerError::OffsetOverflow)?;
    output
        .get_mut(offset..end)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(input);
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, LinkerError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(LinkerError::InvalidCoff)?
            .try_into()
            .map_err(|_| LinkerError::InvalidCoff)?,
    ))
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16, LinkerError> {
    Ok(i16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(LinkerError::InvalidCoff)?
            .try_into()
            .map_err(|_| LinkerError::InvalidCoff)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, LinkerError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(LinkerError::InvalidCoff)?
            .try_into()
            .map_err(|_| LinkerError::InvalidCoff)?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, LinkerError> {
    Ok(i32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(LinkerError::InvalidCoff)?
            .try_into()
            .map_err(|_| LinkerError::InvalidCoff)?,
    ))
}

fn coff_symbol_name<'a>(
    object: &'a [u8],
    symbol_offset: usize,
    strings_offset: usize,
    strings_size: usize,
) -> Result<&'a str, LinkerError> {
    let short = object
        .get(symbol_offset..symbol_offset + 8)
        .ok_or(LinkerError::InvalidCoff)?;
    let bytes = if short[..4] == [0; 4] {
        let offset = usize::try_from(read_u32(object, symbol_offset + 4)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if offset < 4 || offset >= strings_size {
            return Err(LinkerError::InvalidCoff);
        }
        let start = strings_offset
            .checked_add(offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        let end_limit = strings_offset
            .checked_add(strings_size)
            .ok_or(LinkerError::OffsetOverflow)?;
        let tail = object
            .get(start..end_limit)
            .ok_or(LinkerError::InvalidCoff)?;
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(LinkerError::InvalidCoff)?;
        &tail[..length]
    } else {
        let length = short.iter().position(|byte| *byte == 0).unwrap_or(8);
        &short[..length]
    };
    let name = core::str::from_utf8(bytes).map_err(|_| LinkerError::InvalidCoff)?;
    validate_symbol(name)?;
    Ok(name)
}

fn elf_section_header(
    section_offset: usize,
    section_count: usize,
    index: usize,
) -> Result<usize, LinkerError> {
    if index >= section_count {
        return Err(LinkerError::InvalidElf);
    }
    section_offset
        .checked_add(index.checked_mul(64).ok_or(LinkerError::OffsetOverflow)?)
        .ok_or(LinkerError::OffsetOverflow)
}

fn elf_section_contents<'a>(
    object: &'a [u8],
    section_offset: usize,
    section_count: usize,
    index: usize,
) -> Result<&'a [u8], LinkerError> {
    let header = elf_section_header(section_offset, section_count, index)?;
    let offset = to_usize_elf(read_u64_elf(object, header + 24)?)?;
    let size = to_usize_elf(read_u64_elf(object, header + 32)?)?;
    object
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidElf)
}

fn elf_string(strings: &[u8], offset: usize) -> Result<&str, LinkerError> {
    let tail = strings.get(offset..).ok_or(LinkerError::InvalidElf)?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(LinkerError::InvalidElf)?;
    let name = core::str::from_utf8(&tail[..length]).map_err(|_| LinkerError::InvalidElf)?;
    validate_symbol(name)?;
    Ok(name)
}

fn read_u16_elf(bytes: &[u8], offset: usize) -> Result<u16, LinkerError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(LinkerError::InvalidElf)?
            .try_into()
            .map_err(|_| LinkerError::InvalidElf)?,
    ))
}

fn read_u32_elf(bytes: &[u8], offset: usize) -> Result<u32, LinkerError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(LinkerError::InvalidElf)?
            .try_into()
            .map_err(|_| LinkerError::InvalidElf)?,
    ))
}

fn read_u64_elf(bytes: &[u8], offset: usize) -> Result<u64, LinkerError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(LinkerError::InvalidElf)?
            .try_into()
            .map_err(|_| LinkerError::InvalidElf)?,
    ))
}

fn read_i64_elf(bytes: &[u8], offset: usize) -> Result<i64, LinkerError> {
    Ok(i64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(LinkerError::InvalidElf)?
            .try_into()
            .map_err(|_| LinkerError::InvalidElf)?,
    ))
}

fn to_usize_elf(value: u64) -> Result<usize, LinkerError> {
    usize::try_from(value).map_err(|_| LinkerError::OffsetOverflow)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{
        emit_elf64_x86_64, emit_elf64_x86_64_with_readonly_data, emit_elf64_x86_64_with_relocation,
        emit_x86_64_coff, emit_x86_64_coff_with_relocation, MachineCode,
        X86_64PcRelativeRelocation, X86_64PcRelativeRelocationKind,
    };

    fn append_archive_member(archive: &mut std::vec::Vec<u8>, name: &str, bytes: &[u8]) {
        let mut header = [b' '; 60];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = std::format!("{}", bytes.len());
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        archive.extend_from_slice(&header);
        archive.extend_from_slice(bytes);
        if bytes.len() & 1 != 0 {
            archive.push(b'\n');
        }
    }

    #[test]
    fn decodes_ordinary_gnu_and_bsd_archive_member_names() {
        let mut archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut archive, "short.o/", b"one");
        append_archive_member(&mut archive, "//", b"long-object-name.o/\n");
        append_archive_member(&mut archive, "/0", b"two2");
        let mut bsd = b"bsd-name.o".to_vec();
        bsd.extend_from_slice(b"three");
        append_archive_member(&mut archive, "#1/10", &bsd);

        let members = decode_unix_archive(&archive).unwrap();
        assert_eq!(members.members().len(), 3);
        assert_eq!(
            members.members()[0],
            ArchiveMember {
                name: "short.o",
                bytes: b"one"
            }
        );
        assert_eq!(
            members.members()[1],
            ArchiveMember {
                name: "long-object-name.o",
                bytes: b"two2"
            }
        );
        assert_eq!(
            members.members()[2],
            ArchiveMember {
                name: "bsd-name.o",
                bytes: b"three"
            }
        );
    }

    #[test]
    fn skips_archive_symbol_index_metadata() {
        let mut archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut archive, "/", b"index");
        append_archive_member(&mut archive, "/SYM64/", b"wide");
        append_archive_member(&mut archive, "entry.o/", b"object");

        let members = decode_unix_archive(&archive).unwrap();
        assert_eq!(
            members.members(),
            &[ArchiveMember {
                name: "entry.o",
                bytes: b"object"
            }]
        );
    }

    #[test]
    fn rejects_truncated_and_unresolved_archive_members() {
        assert_eq!(
            decode_unix_archive(b"!<arch>\nshort"),
            Err(LinkerError::InvalidArchive)
        );

        let mut archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut archive, "/9", b"object");
        assert_eq!(
            decode_unix_archive(&archive),
            Err(LinkerError::InvalidArchive)
        );
    }

    #[test]
    fn links_forward_and_backward_calls_after_freezing_layout() {
        let to_helper = LinkRelocation {
            offset: 1,
            target: LinkRelocationTarget::Symbol("helper"),
            addend: -4,
        };
        let to_entry = LinkRelocation {
            offset: 1,
            target: LinkRelocationTarget::Symbol("entry"),
            addend: -4,
        };
        let inputs = [
            LinkInput {
                symbol: "entry",
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"A",
                relocations: &[to_helper],
            },
            LinkInput {
                symbol: "helper",
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"B",
                relocations: &[to_entry],
            },
        ];
        let image = link_x86_64_static::<128>(&inputs, "entry").unwrap();
        assert_eq!(image.entry_offset(), 0);
        assert_eq!(image.readonly_offset(), 32);
        assert_eq!(
            i32::from_le_bytes(image.bytes()[1..5].try_into().unwrap()),
            11
        );
        assert_eq!(
            i32::from_le_bytes(image.bytes()[17..21].try_into().unwrap()),
            -21
        );
        assert_eq!(image.bytes()[32], b'A');
        assert_eq!(image.bytes()[48], b'B');
        assert_eq!(image, link_x86_64_static::<128>(&inputs, "entry").unwrap());
    }

    #[test]
    fn rejects_ambiguous_missing_and_out_of_bounds_inputs() {
        let plain = LinkInput {
            symbol: "same",
            text: &[0xc3],
            readonly_data: b"hosted-probe",
            relocations: &[],
        };
        assert_eq!(
            link_x86_64_static::<32>(&[plain, plain], "same"),
            Err(LinkerError::DuplicateSymbol)
        );
        assert_eq!(
            link_x86_64_static::<32>(&[plain], "missing"),
            Err(LinkerError::UndefinedSymbol)
        );
        let bad = LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("same"),
            addend: 0,
        };
        let invalid = LinkInput {
            relocations: &[bad],
            ..plain
        };
        assert_eq!(
            link_x86_64_static::<32>(&[invalid], "same"),
            Err(LinkerError::InvalidRelocationOffset)
        );
        assert_eq!(
            link_x86_64_static::<0>(&[plain], "same"),
            Err(LinkerError::OutputTooSmall)
        );
    }

    #[test]
    fn decodes_and_links_mrml_coff_objects() {
        let caller_code = MachineCode::<8>::from_bytes_for_test(&[0xe8, 0, 0, 0, 0, 0xc3]);
        let callee_code =
            MachineCode::<8>::from_bytes_for_test(&[0x48, 0xc7, 0xc0, 42, 0, 0, 0, 0xc3]);
        let relocation = X86_64PcRelativeRelocation {
            offset: 1,
            symbol: "answer_helper",
            kind: X86_64PcRelativeRelocationKind::Branch,
        };
        let caller =
            emit_x86_64_coff_with_relocation::<256, 8>("entry", &caller_code, relocation).unwrap();
        let callee = emit_x86_64_coff::<192, 8>("answer_helper", &callee_code).unwrap();
        let mut caller_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut callee_relocations = caller_relocations;
        let caller = decode_x86_64_coff(caller.bytes(), &mut caller_relocations).unwrap();
        let callee = decode_x86_64_coff(callee.bytes(), &mut callee_relocations).unwrap();
        let linked = link_x86_64_static::<128>(&[caller, callee], "entry").unwrap();
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[1..5].try_into().unwrap()),
            11
        );
        assert_eq!(&linked.bytes()[16..24], callee_code.bytes());
    }

    #[test]
    fn coff_decoder_fails_closed_on_truncation_machine_and_relocation_type() {
        let code = MachineCode::<8>::from_bytes_for_test(&[0xe8, 0, 0, 0, 0, 0xc3]);
        let relocation = X86_64PcRelativeRelocation {
            offset: 1,
            symbol: "target",
            kind: X86_64PcRelativeRelocationKind::Branch,
        };
        let object =
            emit_x86_64_coff_with_relocation::<256, 8>("entry", &code, relocation).unwrap();
        let empty_storage = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut truncated_storage = empty_storage;
        assert_eq!(
            decode_x86_64_coff(&object.bytes()[..19], &mut truncated_storage),
            Err(LinkerError::InvalidCoff)
        );

        let mut wrong_machine = [0u8; 256];
        wrong_machine[..object.len()].copy_from_slice(object.bytes());
        wrong_machine[0] = 0;
        let mut machine_storage = empty_storage;
        assert_eq!(
            decode_x86_64_coff(&wrong_machine[..object.len()], &mut machine_storage),
            Err(LinkerError::UnsupportedCoff)
        );

        let mut wrong_relocation = wrong_machine;
        wrong_relocation[..object.len()].copy_from_slice(object.bytes());
        let relocation_offset = usize::try_from(read_u32(object.bytes(), 44).unwrap()).unwrap();
        wrong_relocation[relocation_offset + 8..relocation_offset + 10]
            .copy_from_slice(&3u16.to_le_bytes());
        let mut relocation_storage = empty_storage;
        assert_eq!(
            decode_x86_64_coff(&wrong_relocation[..object.len()], &mut relocation_storage),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn decodes_and_links_coff_readonly_section_relocations() {
        use crate::{emit_x86_64_coff_with_readonly_data, X86_64ReadonlyRelocation};

        let code = MachineCode::<8>::from_bytes_for_test(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3]);
        let object = emit_x86_64_coff_with_readonly_data::<256, 8>(
            "literal",
            &code,
            b"hello",
            &[X86_64ReadonlyRelocation {
                offset: 3,
                data_offset: 1,
            }],
        )
        .unwrap();
        let mut storage = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let decoded = decode_x86_64_coff(object.bytes(), &mut storage).unwrap();
        assert_eq!(
            decoded.relocations,
            &[LinkRelocation {
                offset: 3,
                target: LinkRelocationTarget::ReadonlyData(1),
                addend: -4,
            }]
        );
        let linked = link_x86_64_static::<64>(&[decoded], "literal").unwrap();
        assert_eq!(linked.readonly_offset(), 16);
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[3..7].try_into().unwrap()),
            10
        );
        assert_eq!(&linked.bytes()[16..21], b"hello");
    }

    #[test]
    fn emits_deterministic_pe32_plus_with_separate_rx_and_readonly_sections() {
        let relocation = LinkRelocation {
            offset: 3,
            target: LinkRelocationTarget::ReadonlyData(0),
            addend: -4,
        };
        let input = LinkInput {
            symbol: "entry",
            text: &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3],
            readonly_data: b"hello",
            relocations: &[relocation],
        };
        let pe = link_x86_64_pe::<2048, 8192>(&[input], "entry").unwrap();
        assert_eq!(&pe.bytes()[..2], b"MZ");
        assert_eq!(&pe.bytes()[0x80..0x84], b"PE\0\0");
        assert_eq!(read_u16(pe.bytes(), 0x84).unwrap(), 0x8664);
        assert_eq!(read_u16(pe.bytes(), 0x98).unwrap(), 0x20b);
        assert_eq!(read_u32(pe.bytes(), 0xa8).unwrap(), 0x1000);
        assert_eq!(&pe.bytes()[0x188..0x190], b".text\0\0\0");
        assert_eq!(read_u32(pe.bytes(), 0x188 + 36).unwrap(), 0x6000_0020);
        assert_eq!(&pe.bytes()[0x1b0..0x1b8], b".rdata\0\0");
        assert_eq!(read_u32(pe.bytes(), 0x1b0 + 12).unwrap(), 0x2000);
        assert_eq!(read_u32(pe.bytes(), 0x1b0 + 36).unwrap(), 0x4000_0040);
        assert_eq!(
            i32::from_le_bytes(pe.bytes()[0x203..0x207].try_into().unwrap()),
            0xff9
        );
        assert_eq!(&pe.bytes()[0x400..0x405], b"hello");
        assert_eq!(pe, link_x86_64_pe::<2048, 8192>(&[input], "entry").unwrap());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn generated_pe_executes_on_the_controlled_windows_host() {
        let input = LinkInput {
            symbol: "entry",
            text: &[0xb8, 42, 0, 0, 0, 0xc3],
            readonly_data: b"hosted-probe",
            relocations: &[],
        };
        let pe = link_x86_64_pe::<2048, 8192>(&[input], "entry").unwrap();
        let path =
            std::env::temp_dir().join(std::format!("mrml-linker-pe-{}.exe", std::process::id()));
        std::fs::write(&path, pe.bytes()).unwrap();
        let status = std::process::Command::new(&path).status().unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(status.code(), Some(42));
    }

    #[test]
    fn omits_an_empty_readonly_pe_section() {
        let input = LinkInput {
            symbol: "entry",
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let pe = link_x86_64_pe::<1024, 8192>(&[input], "entry").unwrap();
        assert_eq!(read_u16(pe.bytes(), 0x86).unwrap(), 1);
        assert_eq!(read_u32(pe.bytes(), 0xd0).unwrap(), 0x2000);
        assert_eq!(pe.bytes().len(), 0x400);
    }

    #[test]
    fn decodes_and_links_mrml_elf64_objects_and_readonly_data() {
        use crate::X86_64ReadonlyRelocation;

        let caller_code = MachineCode::<8>::from_bytes_for_test(&[0xe8, 0, 0, 0, 0, 0xc3]);
        let callee_code = MachineCode::<8>::from_bytes_for_test(&[0xc3]);
        let external = X86_64PcRelativeRelocation {
            offset: 1,
            symbol: "helper",
            kind: X86_64PcRelativeRelocationKind::Branch,
        };
        let caller =
            emit_elf64_x86_64_with_relocation::<768, 8>("entry", &caller_code, external).unwrap();
        let callee = emit_elf64_x86_64::<512, 8>("helper", &callee_code).unwrap();
        let data_code =
            MachineCode::<8>::from_bytes_for_test(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3]);
        let data = emit_elf64_x86_64_with_readonly_data::<1024, 8>(
            "literal",
            &data_code,
            b"hello",
            &[X86_64ReadonlyRelocation {
                offset: 3,
                data_offset: 1,
            }],
        )
        .unwrap();
        let empty = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut caller_storage = empty;
        let mut callee_storage = empty;
        let mut data_storage = empty;
        let caller = decode_x86_64_elf(caller.bytes(), &mut caller_storage).unwrap();
        let callee = decode_x86_64_elf(callee.bytes(), &mut callee_storage).unwrap();
        let data = decode_x86_64_elf(data.bytes(), &mut data_storage).unwrap();
        assert_eq!(
            data.relocations,
            &[LinkRelocation {
                offset: 3,
                target: LinkRelocationTarget::ReadonlyData(1),
                addend: -4,
            }]
        );
        let linked = link_x86_64_static::<128>(&[caller, callee, data], "entry").unwrap();
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[1..5].try_into().unwrap()),
            11
        );
        assert_eq!(&linked.bytes()[48..53], b"hello");
    }

    #[test]
    fn elf_decoder_rejects_truncation_and_unsupported_machine() {
        let code = MachineCode::<8>::from_bytes_for_test(&[0xc3]);
        let object = emit_elf64_x86_64::<512, 8>("entry", &code).unwrap();
        let empty = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut truncated_storage = empty;
        assert_eq!(
            decode_x86_64_elf(&object.bytes()[..63], &mut truncated_storage),
            Err(LinkerError::InvalidElf)
        );
        let mut wrong_machine = [0u8; 512];
        wrong_machine[..object.len()].copy_from_slice(object.bytes());
        wrong_machine[18..20].copy_from_slice(&3u16.to_le_bytes());
        let mut machine_storage = empty;
        assert_eq!(
            decode_x86_64_elf(&wrong_machine[..object.len()], &mut machine_storage),
            Err(LinkerError::UnsupportedElf)
        );
    }

    #[test]
    fn emits_deterministic_elf64_with_page_separated_load_permissions() {
        let relocation = LinkRelocation {
            offset: 3,
            target: LinkRelocationTarget::ReadonlyData(0),
            addend: -4,
        };
        let input = LinkInput {
            symbol: "entry",
            text: &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3],
            readonly_data: b"hello",
            relocations: &[relocation],
        };
        let elf = link_x86_64_elf_executable::<16384, 8192>(&[input], "entry").unwrap();
        assert_eq!(&elf.bytes()[..9], b"\x7fELF\x02\x01\x01\x00\x00");
        assert_eq!(read_u16_elf(elf.bytes(), 16).unwrap(), 2);
        assert_eq!(read_u16_elf(elf.bytes(), 18).unwrap(), 62);
        assert_eq!(read_u64_elf(elf.bytes(), 24).unwrap(), 0x401000);
        assert_eq!(read_u16_elf(elf.bytes(), 56).unwrap(), 3);
        assert_eq!(read_u32_elf(elf.bytes(), 64 + 4).unwrap(), 4);
        assert_eq!(read_u32_elf(elf.bytes(), 120 + 4).unwrap(), 5);
        assert_eq!(read_u32_elf(elf.bytes(), 176 + 4).unwrap(), 4);
        assert_eq!(read_u64_elf(elf.bytes(), 176 + 8).unwrap(), 0x2000);
        assert_eq!(
            i32::from_le_bytes(elf.bytes()[0x1003..0x1007].try_into().unwrap()),
            0xff9
        );
        assert_eq!(&elf.bytes()[0x2000..0x2005], b"hello");
        assert_eq!(
            elf,
            link_x86_64_elf_executable::<16384, 8192>(&[input], "entry").unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_elf_executes_on_the_controlled_linux_host() {
        use std::os::unix::fs::PermissionsExt;

        let input = LinkInput {
            symbol: "entry",
            text: &[0xbf, 42, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05],
            readonly_data: &[],
            relocations: &[],
        };
        let elf = link_x86_64_elf_executable::<8192, 8192>(&[input], "entry").unwrap();
        let path =
            std::env::temp_dir().join(std::format!("mrml-linker-elf-{}", std::process::id()));
        std::fs::write(&path, elf.bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let status = std::process::Command::new(&path).status().unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(status.code(), Some(42));
    }
}
