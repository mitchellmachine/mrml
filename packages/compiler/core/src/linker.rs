//! Bounded, deterministic x86-64 static-link planning and relocation.
//!
//! The passes deliberately have no shared mutable work between inputs until the
//! final copy/relocation pass. A hosted driver can therefore parallelize input
//! validation and relocation scanning later without changing link semantics.

pub const MAX_LINK_INPUTS: usize = 256;
pub const MAX_LINK_RELOCATIONS: usize = 256;
pub const MAX_LINK_DEFINITIONS: usize = 256;
pub const MAX_PE_RUNTIME_FUNCTIONS: usize = 256;
pub const MAX_ARCHIVE_MEMBERS: usize = MAX_LINK_INPUTS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkerError {
    EmptyInput,
    EmptySymbol,
    SymbolContainsNul,
    TooManyInputs,
    TooManyRelocations,
    TooManyDefinitions,
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
    UnsupportedArchive,
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
            Self::TooManyDefinitions => "link definition capacity exceeded",
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
            Self::UnsupportedArchive => "unsupported Unix archive feature",
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
    if archive.get(..8) == Some(b"!<thin>\n") {
        return Err(LinkerError::UnsupportedArchive);
    }
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
            if !name.starts_with("__.SYMDEF") {
                if decoded.length == MAX_ARCHIVE_MEMBERS {
                    return Err(LinkerError::TooManyArchiveMembers);
                }
                decoded.members[decoded.length] = ArchiveMember { name, bytes };
                decoded.length += 1;
            }
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
    /// A COFF section-scoped code target. It participates in relocation
    /// resolution but never makes an archive member eligible for selection.
    LocalSymbol(&'a str),
    InputText(usize),
    ReadonlyData(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkDefinition<'a> {
    pub symbol: &'a str,
    pub text_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInput<'data, 'relocations, 'definitions> {
    pub symbol: &'data str,
    pub additional_definitions: &'definitions [LinkDefinition<'data>],
    pub text: &'data [u8],
    pub readonly_data: &'data [u8],
    pub relocations: &'relocations [LinkRelocation<'data>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeRuntimeFunction<'a> {
    pub begin_symbol: &'a str,
    pub begin_offset: usize,
    pub end_symbol: &'a str,
    pub end_offset: usize,
    pub unwind_info: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeWritableRelocation<'a> {
    pub offset: usize,
    pub target_readonly_owner: &'a str,
    pub target_readonly_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeWritableData<'a, 'relocations> {
    pub bytes: &'a [u8],
    pub relocations: &'relocations [PeWritableRelocation<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInputSelection {
    indices: [usize; MAX_LINK_INPUTS],
    length: usize,
}

impl LinkInputSelection {
    pub fn indices(&self) -> &[usize] {
        &self.indices[..self.length]
    }
}

/// Selects explicit objects and the archive members needed by the entry or by
/// a selected input's named relocations. The stable fixed point is independent
/// of archive symbol-index encoding and preserves candidate order.
pub fn select_static_link_inputs(
    inputs: &[LinkInput<'_, '_, '_>],
    archive_member: &[bool],
    entry_symbol: &str,
) -> Result<LinkInputSelection, LinkerError> {
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_INPUTS || inputs.len() != archive_member.len() {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;
    let mut selected = [false; MAX_LINK_INPUTS];
    for index in 0..inputs.len() {
        selected[index] = !archive_member[index];
    }
    loop {
        let mut changed = false;
        for candidate in 0..inputs.len() {
            if selected[candidate] || !archive_member[candidate] {
                continue;
            }
            let needed = core::iter::once(LinkDefinition {
                symbol: inputs[candidate].symbol,
                text_offset: 0,
            })
            .chain(inputs[candidate].additional_definitions.iter().copied())
            .any(|definition| {
                !symbol_is_defined(inputs, &selected, definition.symbol)
                    && (definition.symbol == entry_symbol
                        || symbol_is_referenced(inputs, &selected, definition.symbol))
            });
            if needed {
                selected[candidate] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut selection = LinkInputSelection {
        indices: [0; MAX_LINK_INPUTS],
        length: 0,
    };
    for index in 0..inputs.len() {
        if selected[index] {
            selection.indices[selection.length] = index;
            selection.length += 1;
        }
    }
    Ok(selection)
}

/// Applies conventional left-to-right static archive selection. Group zero is
/// an explicit object; each nonzero value identifies one contiguous archive.
/// An archive is rescanned to its own fixed point and is not revisited after a
/// later object or archive introduces another unresolved symbol.
pub fn select_ordered_static_link_inputs(
    inputs: &[LinkInput<'_, '_, '_>],
    archive_group: &[u16],
    entry_symbol: &str,
) -> Result<LinkInputSelection, LinkerError> {
    if inputs.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs);
    }
    let mut archive_member = [0u16; MAX_LINK_INPUTS];
    for index in 0..inputs.len() {
        if archive_group.get(index).copied().unwrap_or(0) != 0 {
            archive_member[index] =
                u16::try_from(index + 1).map_err(|_| LinkerError::TooManyInputs)?;
        }
    }
    select_ordered_static_link_members(
        inputs,
        archive_group,
        &archive_member[..inputs.len()],
        entry_symbol,
    )
}

/// Applies conventional left-to-right archive selection while treating every
/// fragment with the same nonzero `(archive_group, archive_member)` pair as one
/// object member. Selecting any definition in that member selects all of its
/// code and metadata fragments atomically.
pub fn select_ordered_static_link_members(
    inputs: &[LinkInput<'_, '_, '_>],
    archive_group: &[u16],
    archive_member: &[u16],
    entry_symbol: &str,
) -> Result<LinkInputSelection, LinkerError> {
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_INPUTS
        || inputs.len() != archive_group.len()
        || inputs.len() != archive_member.len()
    {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;
    let mut selected = [false; MAX_LINK_INPUTS];
    let mut cursor = 0usize;
    while cursor < inputs.len() {
        let group = archive_group[cursor];
        if group == 0 {
            if archive_member[cursor] != 0 {
                return Err(LinkerError::InvalidArchive);
            }
            selected[cursor] = true;
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < inputs.len() && archive_group[cursor] == group {
            cursor += 1;
        }
        if archive_group[..start].contains(&group) {
            return Err(LinkerError::InvalidArchive);
        }
        if archive_member[start..cursor].contains(&0) {
            return Err(LinkerError::InvalidArchive);
        }
        loop {
            let mut changed = false;
            for candidate in start..cursor {
                if selected[candidate] {
                    continue;
                }
                let needed = core::iter::once(LinkDefinition {
                    symbol: inputs[candidate].symbol,
                    text_offset: 0,
                })
                .chain(inputs[candidate].additional_definitions.iter().copied())
                .any(|definition| {
                    !symbol_is_defined(inputs, &selected, definition.symbol)
                        && (definition.symbol == entry_symbol
                            || symbol_is_referenced(inputs, &selected, definition.symbol))
                });
                if needed {
                    let member = archive_member[candidate];
                    for sibling in start..cursor {
                        if archive_member[sibling] == member {
                            selected[sibling] = true;
                        }
                    }
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
    let mut selection = LinkInputSelection {
        indices: [0; MAX_LINK_INPUTS],
        length: 0,
    };
    for index in 0..inputs.len() {
        if selected[index] {
            selection.indices[selection.length] = index;
            selection.length += 1;
        }
    }
    Ok(selection)
}

fn symbol_is_defined(
    inputs: &[LinkInput<'_, '_, '_>],
    selected: &[bool; MAX_LINK_INPUTS],
    symbol: &str,
) -> bool {
    inputs
        .iter()
        .enumerate()
        .any(|(index, input)| selected[index] && input_definition_offset(input, symbol).is_some())
}

fn input_definition_offset(input: &LinkInput<'_, '_, '_>, symbol: &str) -> Option<usize> {
    if input.symbol == symbol {
        return Some(0);
    }
    input
        .additional_definitions
        .iter()
        .find(|definition| definition.symbol == symbol)
        .map(|definition| definition.text_offset)
}

fn symbol_is_referenced(
    inputs: &[LinkInput<'_, '_, '_>],
    selected: &[bool; MAX_LINK_INPUTS],
    symbol: &str,
) -> bool {
    inputs.iter().enumerate().any(|(index, input)| {
        selected[index]
            && input.relocations.iter().any(|relocation| {
                matches!(relocation.target, LinkRelocationTarget::Symbol(target) if target == symbol)
            })
    })
}

/// Decodes the bounded x86-64 COFF subset emitted by `mrml-rustc` into the
/// format-neutral static-link input. The caller owns relocation storage so the
/// dependency-free compiler core never allocates.
pub fn decode_x86_64_coff<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<LinkInput<'data, 'relocations, 'data>, LinkerError> {
    let mut definitions = [LinkDefinition {
        symbol: "unused",
        text_offset: 0,
    }; MAX_LINK_DEFINITIONS];
    let decoded =
        decode_x86_64_coff_with_definitions(object, relocation_storage, &mut definitions)?;
    if !decoded.additional_definitions.is_empty() {
        return Err(LinkerError::UnsupportedCoff);
    }
    Ok(LinkInput {
        symbol: decoded.symbol,
        additional_definitions: &[],
        text: decoded.text,
        readonly_data: decoded.readonly_data,
        relocations: decoded.relocations,
    })
}

pub fn decode_x86_64_coff_with_definitions<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
    if x86_64_coff_text_fragment_count(object)? != 1
        || x86_64_coff_unwind_section_count(object)? != 0
        || x86_64_coff_writable_section_count(object)? != 0
    {
        return Err(LinkerError::UnsupportedCoff);
    }
    decode_x86_64_coff_text_fragment(object, 0, relocation_storage, definition_storage)
}

/// Counts nonempty `.text`/`.text$...` fragments in a bounded AMD64 COFF
/// object. This is a structural query only; decoding a requested fragment still
/// validates all admitted sections, symbols, and relocations.
pub fn x86_64_coff_text_fragment_count(object: &[u8]) -> Result<usize, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let mut fragments = 0usize;
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
    let string_size =
        usize::try_from(read_u32(object, symbols_end)?).map_err(|_| LinkerError::OffsetOverflow)?;
    if string_size < 4 {
        return Err(LinkerError::InvalidCoff);
    }
    object
        .get(
            symbols_end
                ..symbols_end
                    .checked_add(string_size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidCoff)?;
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let raw_name = object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?;
        let name = coff_section_name(raw_name, object, symbols_end, string_size)?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if (name == ".text" || name.starts_with(".text$")) && size != 0 {
            fragments = fragments
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    if fragments == 0 {
        return Err(LinkerError::InvalidCoff);
    }
    Ok(fragments)
}

/// Counts nonempty `.pdata$...` and `.xdata$...` sections without interpreting
/// their contents. Legacy single-fragment decoding uses this to reject objects
/// whose unwind metadata would otherwise be lost.
pub fn x86_64_coff_unwind_section_count(object: &[u8]) -> Result<usize, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
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
    let string_size =
        usize::try_from(read_u32(object, symbols_end)?).map_err(|_| LinkerError::OffsetOverflow)?;
    if string_size < 4 {
        return Err(LinkerError::InvalidCoff);
    }
    object
        .get(
            symbols_end
                ..symbols_end
                    .checked_add(string_size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidCoff)?;
    let mut unwind_sections = 0usize;
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let raw_name = object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?;
        let name = coff_section_name(raw_name, object, symbols_end, string_size)?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if (name.starts_with(".pdata$") || name.starts_with(".xdata$")) && size != 0 {
            unwind_sections = unwind_sections
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(unwind_sections)
}

pub fn x86_64_coff_writable_section_count(object: &[u8]) -> Result<usize, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
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
    let string_size =
        usize::try_from(read_u32(object, symbols_end)?).map_err(|_| LinkerError::OffsetOverflow)?;
    if string_size < 4 {
        return Err(LinkerError::InvalidCoff);
    }
    object
        .get(
            symbols_end
                ..symbols_end
                    .checked_add(string_size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidCoff)?;
    let mut count = 0usize;
    for section in 0..section_count {
        let header = 20 + section * 40;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            symbols_end,
            string_size,
        )?;
        if name.starts_with(".data$") && read_u32(object, header + 16)? != 0 {
            count = count.checked_add(1).ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(count)
}

pub fn decode_x86_64_coff_writable_data<'data, 'relocations>(
    object: &'data [u8],
    readonly_owner: &'data str,
    relocation_storage: &'relocations mut [PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<Option<PeWritableData<'data, 'relocations>>, LinkerError> {
    match x86_64_coff_writable_section_count(object)? {
        0 => Ok(None),
        1 => {
            decode_x86_64_coff_writable_data_fragment(object, 0, readonly_owner, relocation_storage)
                .map(Some)
        }
        _ => Err(LinkerError::UnsupportedCoff),
    }
}

pub fn decode_x86_64_coff_writable_data_fragment<'data, 'relocations>(
    object: &'data [u8],
    fragment_index: usize,
    readonly_owner: &'data str,
    relocation_storage: &'relocations mut [PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<PeWritableData<'data, 'relocations>, LinkerError> {
    validate_symbol(readonly_owner)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
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
    object
        .get(
            symbols_end
                ..symbols_end
                    .checked_add(string_size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidCoff)?;

    let mut readonly_sections = [false; 17];
    let mut readonly_span = None;
    let mut writable = None;
    let mut writable_ordinal = 0usize;
    for section in 0..section_count {
        let header = 20 + section * 40;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            symbols_end,
            string_size,
        )?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if size == 0 {
            continue;
        }
        if name == ".rdata" || name.starts_with(".rdata$") {
            let raw = usize::try_from(read_u32(object, header + 20)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let end = raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?;
            object.get(raw..end).ok_or(LinkerError::InvalidCoff)?;
            readonly_sections[section + 1] = true;
            readonly_span = Some(match readonly_span {
                None => (raw, end),
                Some((start, previous_end)) if previous_end == raw => (start, end),
                Some(_) => return Err(LinkerError::UnsupportedCoff),
            });
        } else if name.starts_with(".data$") {
            let characteristics = read_u32(object, header + 36)?;
            if characteristics & 0xe000_0060 != 0xc000_0040 {
                return Err(LinkerError::UnsupportedCoff);
            }
            if writable_ordinal == fragment_index {
                let raw = usize::try_from(read_u32(object, header + 20)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let bytes = object
                    .get(raw..raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?)
                    .ok_or(LinkerError::InvalidCoff)?;
                writable = Some((
                    bytes,
                    usize::try_from(read_u32(object, header + 24)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                    usize::from(read_u16(object, header + 32)?),
                ));
            }
            writable_ordinal = writable_ordinal
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    let (bytes, relocation_offset, relocation_count) = writable.ok_or(LinkerError::InvalidCoff)?;
    let readonly_start = readonly_span.ok_or(LinkerError::UnsupportedCoff)?.0;
    if relocation_count > relocation_storage.len() {
        return Err(LinkerError::TooManyRelocations);
    }
    for (index, slot) in relocation_storage[..relocation_count]
        .iter_mut()
        .enumerate()
    {
        let relocation = relocation_offset
            .checked_add(index.checked_mul(10).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let field_offset = usize::try_from(read_u32(object, relocation)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if field_offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .is_none()
            || read_u16(object, relocation + 8)? != 1
        {
            return Err(LinkerError::UnsupportedCoff);
        }
        let target_index = usize::try_from(read_u32(object, relocation + 4)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if target_index >= symbol_count {
            return Err(LinkerError::InvalidCoff);
        }
        let target = symbol_offset + target_index * 18;
        let target_section = read_i16(object, target + 12)?;
        let target_section_index =
            usize::try_from(target_section).map_err(|_| LinkerError::UnsupportedCoff)?;
        if !readonly_sections
            .get(target_section_index)
            .copied()
            .unwrap_or(false)
        {
            return Err(LinkerError::UnsupportedCoff);
        }
        let target_header = 20 + (target_section_index - 1) * 40;
        let target_raw = usize::try_from(read_u32(object, target_header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let target_value = u64::from(read_u32(object, target + 8)?);
        let addend = read_u64_coff(bytes, field_offset)?;
        let target_readonly_offset = usize::try_from(
            u64::try_from(
                target_raw
                    .checked_sub(readonly_start)
                    .ok_or(LinkerError::InvalidCoff)?,
            )
            .map_err(|_| LinkerError::OffsetOverflow)?
            .checked_add(target_value)
            .ok_or(LinkerError::OffsetOverflow)?
            .checked_add(addend)
            .ok_or(LinkerError::OffsetOverflow)?,
        )
        .map_err(|_| LinkerError::OffsetOverflow)?;
        *slot = PeWritableRelocation {
            offset: field_offset,
            target_readonly_owner: readonly_owner,
            target_readonly_offset,
        };
    }
    Ok(PeWritableData {
        bytes,
        relocations: &relocation_storage[..relocation_count],
    })
}

/// Decodes the bounded AMD64 `.pdata$...`/`.xdata$...` shape emitted by the
/// pinned gnullvm oracle. Every 12-byte runtime-function record must carry
/// three `IMAGE_REL_AMD64_ADDR32NB` relocations at its three fields.
pub fn decode_x86_64_coff_runtime_functions<'data, 'records>(
    object: &'data [u8],
    record_storage: &'records mut [PeRuntimeFunction<'data>; MAX_PE_RUNTIME_FUNCTIONS],
) -> Result<&'records [PeRuntimeFunction<'data>], LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
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
    object
        .get(
            symbols_end
                ..symbols_end
                    .checked_add(string_size)
                    .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::InvalidCoff)?;

    let mut record_count = 0usize;
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            symbols_end,
            string_size,
        )?;
        if !name.starts_with(".pdata$") {
            continue;
        }
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let raw_offset = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let records = object
            .get(
                raw_offset
                    ..raw_offset
                        .checked_add(size)
                        .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::InvalidCoff)?;
        if records.is_empty() || records.len() % 12 != 0 {
            return Err(LinkerError::UnsupportedCoff);
        }
        let relocation_offset = usize::try_from(read_u32(object, header + 24)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let relocation_count = usize::from(read_u16(object, header + 32)?);
        if relocation_count != records.len() / 4 {
            return Err(LinkerError::UnsupportedCoff);
        }
        for record_index in 0..records.len() / 12 {
            if record_count == record_storage.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let mut text_targets = [("", 0usize); 2];
            let mut unwind_info = None;
            for field in 0..3 {
                let relocation = relocation_offset
                    .checked_add(
                        (record_index * 3 + field)
                            .checked_mul(10)
                            .ok_or(LinkerError::OffsetOverflow)?,
                    )
                    .ok_or(LinkerError::OffsetOverflow)?;
                let expected_field = record_index * 12 + field * 4;
                if usize::try_from(read_u32(object, relocation)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?
                    != expected_field
                    || read_u16(object, relocation + 8)? != 3
                {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let target_index = usize::try_from(read_u32(object, relocation + 4)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                if target_index >= symbol_count {
                    return Err(LinkerError::InvalidCoff);
                }
                let target = symbol_offset + target_index * 18;
                let target_section = read_i16(object, target + 12)?;
                if target_section <= 0
                    || usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?
                        > section_count
                {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let target_value = usize::try_from(read_u32(object, target + 8)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let addend = usize::try_from(read_u32(records, expected_field)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?
                    .checked_add(target_value)
                    .ok_or(LinkerError::OffsetOverflow)?;
                let target_header = 20usize
                    .checked_add(
                        (usize::try_from(target_section)
                            .map_err(|_| LinkerError::OffsetOverflow)?
                            - 1)
                            * 40,
                    )
                    .ok_or(LinkerError::OffsetOverflow)?;
                let target_name = coff_section_name(
                    object
                        .get(target_header..target_header + 8)
                        .ok_or(LinkerError::InvalidCoff)?,
                    object,
                    symbols_end,
                    string_size,
                )?;
                if field < 2 {
                    if target_name != ".text" && !target_name.starts_with(".text$") {
                        return Err(LinkerError::UnsupportedCoff);
                    }
                    let symbol = coff_code_symbol_in_section(
                        object,
                        symbol_offset,
                        symbol_count,
                        symbols_end,
                        string_size,
                        target_section,
                    )?;
                    text_targets[field] = (symbol, addend);
                } else {
                    if !target_name.starts_with(".xdata$") || addend != 0 {
                        return Err(LinkerError::UnsupportedCoff);
                    }
                    let target_size = usize::try_from(read_u32(object, target_header + 16)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?;
                    let target_raw = usize::try_from(read_u32(object, target_header + 20)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?;
                    let bytes = object
                        .get(
                            target_raw
                                ..target_raw
                                    .checked_add(target_size)
                                    .ok_or(LinkerError::OffsetOverflow)?,
                        )
                        .ok_or(LinkerError::InvalidCoff)?;
                    if bytes.is_empty() {
                        return Err(LinkerError::UnsupportedCoff);
                    }
                    unwind_info = Some(bytes);
                }
            }
            record_storage[record_count] = PeRuntimeFunction {
                begin_symbol: text_targets[0].0,
                begin_offset: text_targets[0].1,
                end_symbol: text_targets[1].0,
                end_offset: text_targets[1].1,
                unwind_info: unwind_info.ok_or(LinkerError::UnsupportedCoff)?,
            };
            record_count += 1;
        }
    }
    Ok(&record_storage[..record_count])
}

fn coff_code_symbol_in_section<'a>(
    object: &'a [u8],
    symbol_offset: usize,
    symbol_count: usize,
    strings_offset: usize,
    string_size: usize,
    section: i16,
) -> Result<&'a str, LinkerError> {
    let mut index = 0usize;
    let mut found = None;
    while index < symbol_count {
        let offset = symbol_offset + index * 18;
        let auxiliary = usize::from(*object.get(offset + 17).ok_or(LinkerError::InvalidCoff)?);
        if read_i16(object, offset + 12)? == section
            && *object.get(offset + 16).ok_or(LinkerError::InvalidCoff)? == 2
            && read_u32(object, offset + 8)? == 0
        {
            let symbol = coff_symbol_name(object, offset, strings_offset, string_size)?;
            if found.replace(symbol).is_some() {
                return Err(LinkerError::UnsupportedCoff);
            }
        }
        index = index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if let Some(symbol) = found {
        return Ok(symbol);
    }
    let section_index = usize::try_from(section).map_err(|_| LinkerError::UnsupportedCoff)?;
    if section_index == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let header = 20usize
        .checked_add(
            (section_index - 1)
                .checked_mul(40)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    coff_section_name(
        object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?,
        object,
        strings_offset,
        string_size,
    )
}

/// Decodes one nonempty COFF text fragment by section order. Unwind sections
/// are validated and retained for the separate typed unwind decoder; they are
/// never folded into executable bytes or silently treated as ordinary data.
pub fn decode_x86_64_coff_text_fragment<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 || section_count > 16 {
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
    let mut text_section = None;
    let mut text_section_name = None;
    let mut readonly_data = &object[0..0];
    let mut readonly_sections = [false; 17];
    let mut readonly_span = None;
    let mut ignored_empty_sections = [false; 17];
    let mut other_text_sections = [false; 17];
    let mut unwind_sections = [false; 17];
    let mut writable_sections = [false; 17];
    let mut metadata_sections = [false; 17];
    let mut relocation_table = (0usize, 0usize);
    let mut text_ordinal = 0usize;
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let raw_name = object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?;
        let name = coff_section_name(raw_name, object, symbols_end, string_size)?;
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
        let section_number = i16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        if name == ".text" || name.starts_with(".text$") {
            if contents.is_empty() {
                ignored_empty_sections[section + 1] = true;
                continue;
            }
            other_text_sections[section + 1] = true;
            if text_ordinal == fragment_index {
                text = Some(contents);
                text_section = Some(section_number);
                text_section_name = Some(name);
                relocation_table = (
                    usize::try_from(read_u32(object, header + 24)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                    usize::from(read_u16(object, header + 32)?),
                );
            }
            text_ordinal += 1;
        } else if name == ".rdata" || name.starts_with(".rdata$") {
            if contents.is_empty() {
                ignored_empty_sections[section + 1] = true;
                continue;
            }
            readonly_sections[section + 1] = true;
            readonly_span = Some(match readonly_span {
                None => (offset, offset + size),
                Some((start, end)) if end == offset => (start, offset + size),
                Some(_) => return Err(LinkerError::UnsupportedCoff),
            });
            let (start, end) = readonly_span.ok_or(LinkerError::InvalidCoff)?;
            readonly_data = object.get(start..end).ok_or(LinkerError::InvalidCoff)?;
        } else if name.starts_with(".xdata$") || name.starts_with(".pdata$") {
            unwind_sections[section + 1] = true;
        } else if name.starts_with(".data$") && !contents.is_empty() {
            writable_sections[section + 1] = true;
        } else if name == ".llvmbc" || name == ".llvmcmd" {
            let characteristics = read_u32(object, header + 36)?;
            let relocation_count = read_u16(object, header + 32)?;
            if characteristics & 0x0000_0800 == 0 || relocation_count != 0 {
                return Err(LinkerError::UnsupportedCoff);
            }
            metadata_sections[section + 1] = true;
        } else if (name == ".data" || name == ".bss") && contents.is_empty() {
            ignored_empty_sections[section + 1] = true;
        } else {
            return Err(LinkerError::UnsupportedCoff);
        }
    }
    let text = text.ok_or(LinkerError::InvalidCoff)?;
    let text_section = text_section.ok_or(LinkerError::InvalidCoff)?;

    let mut defined_symbol = None;
    let mut definition_count = 0usize;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let offset = symbol_offset + symbol_index * 18;
        let section = read_i16(object, offset + 12)?;
        let storage_class = *object.get(offset + 16).ok_or(LinkerError::InvalidCoff)?;
        let auxiliary = usize::from(*object.get(offset + 17).ok_or(LinkerError::InvalidCoff)?);
        if section == text_section && storage_class == 2 {
            let name = coff_symbol_name(object, offset, symbols_end, string_size)?;
            let text_offset = usize::try_from(read_u32(object, offset + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidCoff);
            }
            if text_offset == 0 && defined_symbol.is_none() {
                defined_symbol = Some(name);
            } else {
                if definition_count == definition_storage.len() {
                    return Err(LinkerError::TooManyDefinitions);
                }
                definition_storage[definition_count] = LinkDefinition {
                    symbol: name,
                    text_offset,
                };
                definition_count += 1;
            }
        } else if section == text_section && storage_class == 3 {
            let text_offset = usize::try_from(read_u32(object, offset + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidCoff);
            }
        } else if (section == -1 && storage_class == 3) || (section == -2 && storage_class == 103) {
        } else if section > 0
            && ignored_empty_sections
                .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                .copied()
                .unwrap_or(false)
        {
        } else if section > 0
            && (other_text_sections
                .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                .copied()
                .unwrap_or(false)
                || unwind_sections
                    .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                    .copied()
                    .unwrap_or(false)
                || writable_sections
                    .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                    .copied()
                    .unwrap_or(false)
                || metadata_sections
                    .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                    .copied()
                    .unwrap_or(false))
        {
        } else if section > 0
            && readonly_sections
                .get(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                .copied()
                .unwrap_or(false)
        {
        } else if section != 0 {
            return Err(LinkerError::UnsupportedCoff);
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let symbol = defined_symbol
        .or(text_section_name)
        .ok_or(LinkerError::InvalidCoff)?;

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
        } else if target_section == text_section {
            let text_offset = usize::try_from(read_u32(object, target_offset + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidRelocationOffset);
            }
            (
                LinkRelocationTarget::InputText(text_offset),
                i64::from(field_addend) - 4,
            )
        } else if target_section > 0
            && other_text_sections
                .get(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
                .copied()
                .unwrap_or(false)
        {
            let storage_class = *object
                .get(target_offset + 16)
                .ok_or(LinkerError::InvalidCoff)?;
            let target = if storage_class == 2 {
                LinkRelocationTarget::Symbol(coff_symbol_name(
                    object,
                    target_offset,
                    symbols_end,
                    string_size,
                )?)
            } else if storage_class == 3 {
                let target_header = 20
                    + (usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?
                        - 1)
                        * 40;
                LinkRelocationTarget::LocalSymbol(coff_section_name(
                    object
                        .get(target_header..target_header + 8)
                        .ok_or(LinkerError::InvalidCoff)?,
                    object,
                    symbols_end,
                    string_size,
                )?)
            } else {
                return Err(LinkerError::UnsupportedCoff);
            };
            (target, i64::from(field_addend) - 4)
        } else if target_section > 0
            && readonly_sections
                .get(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
                .copied()
                .unwrap_or(false)
        {
            let target_header = 20
                + (usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)? - 1)
                    * 40;
            let target_raw = usize::try_from(read_u32(object, target_header + 20)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let readonly_start = readonly_span.ok_or(LinkerError::InvalidCoff)?.0;
            let symbol_value = usize::try_from(read_u32(object, target_offset + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let field_addend =
                usize::try_from(field_addend).map_err(|_| LinkerError::InvalidRelocationOffset)?;
            let data_offset = target_raw
                .checked_sub(readonly_start)
                .and_then(|offset| offset.checked_add(symbol_value))
                .and_then(|offset| offset.checked_add(field_addend))
                .ok_or(LinkerError::OffsetOverflow)?;
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
        additional_definitions: &definition_storage[..definition_count],
        text,
        readonly_data,
        relocations: &relocation_storage[..relocation_table.1],
    })
}

/// Decodes the exact bounded ELF64 relocatable subset emitted by `mrml-rustc`.
pub fn decode_x86_64_elf<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<LinkInput<'data, 'relocations, 'data>, LinkerError> {
    let mut definitions = [LinkDefinition {
        symbol: "unused",
        text_offset: 0,
    }; MAX_LINK_DEFINITIONS];
    let decoded = decode_x86_64_elf_with_definitions(object, relocation_storage, &mut definitions)?;
    if !decoded.additional_definitions.is_empty() {
        return Err(LinkerError::UnsupportedElf);
    }
    Ok(LinkInput {
        symbol: decoded.symbol,
        additional_definitions: &[],
        text: decoded.text,
        readonly_data: decoded.readonly_data,
        relocations: decoded.relocations,
    })
}

pub fn decode_x86_64_elf_with_definitions<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
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
    let mut definition_count = 0usize;
    for index in 1..symbol_count {
        let offset = index * 24;
        let section = usize::from(read_u16_elf(symbols, offset + 6)?);
        let binding = *symbols.get(offset + 4).ok_or(LinkerError::InvalidElf)? >> 4;
        if section == text_index && binding == 1 {
            let text_offset = to_usize_elf(read_u64_elf(symbols, offset + 8)?)?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidElf);
            }
            let name = elf_string(
                strings,
                usize::try_from(read_u32_elf(symbols, offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
            if text_offset == 0 && defined_symbol.is_none() {
                defined_symbol = Some(name);
            } else {
                if definition_count == definition_storage.len() {
                    return Err(LinkerError::TooManyDefinitions);
                }
                definition_storage[definition_count] = LinkDefinition {
                    symbol: name,
                    text_offset,
                };
                definition_count += 1;
            }
        } else if section == text_index && binding == 0 {
            let text_offset = to_usize_elf(read_u64_elf(symbols, offset + 8)?)?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidElf);
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
            } else if target_section == text_index {
                let text_offset = to_usize_elf(read_u64_elf(symbols, target_offset + 8)?)?;
                if text_offset > text.len() {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                (LinkRelocationTarget::InputText(text_offset), encoded_addend)
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
        additional_definitions: &definition_storage[..definition_count],
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
    layouts: [InputLayout; MAX_LINK_INPUTS],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputLayout {
    text: usize,
    readonly: usize,
}

/// Links already-decoded MRML x86-64 fragments into one position-independent
/// image. Input order is significant and makes the result reproducible.
pub fn link_x86_64_static<const MAX_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
) -> Result<LinkedImage<MAX_BYTES>, LinkerError> {
    link_x86_64_static_aligned(inputs, entry_symbol, 16)
}

/// Links MRML COFF fragments and writes a deterministic, import-free PE32+
/// executable with separate RX code and read-only NX data sections.
pub fn link_x86_64_pe<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
) -> Result<PeImage<MAX_IMAGE_BYTES>, LinkerError> {
    link_x86_64_pe_with_unwind::<MAX_IMAGE_BYTES, MAX_LINKED_BYTES>(inputs, entry_symbol, &[])
}

/// Writes PE32+ exception metadata from bounded typed runtime-function records.
/// Records are sorted by resolved begin RVA and their unwind bytes remain in
/// the read-only, non-executable section.
pub fn link_x86_64_pe_with_unwind<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
    runtime_functions: &[PeRuntimeFunction<'_>],
) -> Result<PeImage<MAX_IMAGE_BYTES>, LinkerError> {
    link_x86_64_pe_with_data_and_unwind::<MAX_IMAGE_BYTES, MAX_LINKED_BYTES>(
        inputs,
        entry_symbol,
        runtime_functions,
        &[],
    )
}

pub fn link_x86_64_pe_with_data_and_unwind<
    const MAX_IMAGE_BYTES: usize,
    const MAX_LINKED_BYTES: usize,
>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
) -> Result<PeImage<MAX_IMAGE_BYTES>, LinkerError> {
    const FILE_ALIGNMENT: usize = 0x200;
    const SECTION_ALIGNMENT: usize = 0x1000;
    const HEADERS: usize = 0x200;
    const TEXT_RVA: usize = 0x1000;
    const IMAGE_BASE: usize = 0x0000_0001_4000_0000;

    let linked =
        link_x86_64_static_aligned::<MAX_LINKED_BYTES>(inputs, entry_symbol, SECTION_ALIGNMENT)?;
    if runtime_functions.len() > MAX_PE_RUNTIME_FUNCTIONS {
        return Err(LinkerError::TooManyRelocations);
    }
    let text_size = linked.text_length;
    let linked_readonly_size = linked.length - linked.readonly_offset;
    let mut unwind_offsets = [0usize; MAX_PE_RUNTIME_FUNCTIONS];
    let mut readonly_size = linked_readonly_size;
    for (index, function) in runtime_functions.iter().enumerate() {
        validate_symbol(function.begin_symbol)?;
        validate_symbol(function.end_symbol)?;
        if function.unwind_info.is_empty() {
            return Err(LinkerError::InvalidCoff);
        }
        readonly_size = align(readonly_size, 4)?;
        unwind_offsets[index] = readonly_size;
        readonly_size = readonly_size
            .checked_add(function.unwind_info.len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let pdata_offset = align(readonly_size, 4)?;
    readonly_size = pdata_offset
        .checked_add(
            runtime_functions
                .len()
                .checked_mul(12)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    if writable_data.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs);
    }
    let mut writable_offsets = [0usize; MAX_LINK_INPUTS];
    let mut writable_size = 0usize;
    for (index, data) in writable_data.iter().enumerate() {
        if data.bytes.is_empty() {
            return Err(LinkerError::InvalidCoff);
        }
        writable_size = align(writable_size, 8)?;
        writable_offsets[index] = writable_size;
        writable_size = writable_size
            .checked_add(data.bytes.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        for relocation in data.relocations {
            validate_symbol(relocation.target_readonly_owner)?;
            relocation
                .offset
                .checked_add(8)
                .filter(|end| *end <= data.bytes.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
        }
    }
    let text_raw_size = align(text_size, FILE_ALIGNMENT)?;
    let readonly_raw_size = align(readonly_size, FILE_ALIGNMENT)?;
    let readonly_raw = HEADERS
        .checked_add(text_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    let writable_raw_size = align(writable_size, FILE_ALIGNMENT)?;
    let writable_raw = readonly_raw
        .checked_add(readonly_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    let length = writable_raw
        .checked_add(writable_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    if length > MAX_IMAGE_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    let readonly_rva = TEXT_RVA
        .checked_add(linked.readonly_offset)
        .ok_or(LinkerError::OffsetOverflow)?;
    let writable_rva = if readonly_size == 0 {
        readonly_rva
    } else {
        align(
            readonly_rva
                .checked_add(readonly_size)
                .ok_or(LinkerError::OffsetOverflow)?,
            SECTION_ALIGNMENT,
        )?
    };
    let size_of_image = if writable_size != 0 {
        align(
            writable_rva
                .checked_add(writable_size)
                .ok_or(LinkerError::OffsetOverflow)?,
            SECTION_ALIGNMENT,
        )?
    } else if readonly_size == 0 {
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
    let section_count = 1 + usize::from(readonly_size != 0) + usize::from(writable_size != 0);
    patch_u16(
        &mut bytes,
        0x86,
        u16::try_from(section_count).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u16(&mut bytes, 0x94, 240)?;
    patch_u16(&mut bytes, 0x96, 0x0023)?;

    let optional = 0x98;
    patch_u16(&mut bytes, optional, 0x20b)?;
    patch_u32(&mut bytes, optional + 4, to_u32_link(text_raw_size)?)?;
    patch_u32(
        &mut bytes,
        optional + 8,
        to_u32_link(
            readonly_raw_size
                .checked_add(writable_raw_size)
                .ok_or(LinkerError::OffsetOverflow)?,
        )?,
    )?;
    patch_u32(
        &mut bytes,
        optional + 16,
        to_u32_link(TEXT_RVA + linked.entry_offset)?,
    )?;
    patch_u32(&mut bytes, optional + 20, to_u32_link(TEXT_RVA)?)?;
    patch_u64(
        &mut bytes,
        optional + 24,
        u64::try_from(IMAGE_BASE).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
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
    if !runtime_functions.is_empty() {
        patch_u32(
            &mut bytes,
            optional + 136,
            to_u32_link(readonly_rva + pdata_offset)?,
        )?;
        patch_u32(
            &mut bytes,
            optional + 140,
            to_u32_link(runtime_functions.len() * 12)?,
        )?;
    }

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
    if writable_size != 0 {
        write_pe_section(
            &mut bytes,
            if readonly_size == 0 { 0x1b0 } else { 0x1d8 },
            b".data\0\0\0",
            writable_size,
            writable_rva,
            writable_raw_size,
            writable_raw,
            0xc000_0040,
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
    let mut begin_rvas = [0u32; MAX_PE_RUNTIME_FUNCTIONS];
    let mut end_rvas = [0u32; MAX_PE_RUNTIME_FUNCTIONS];
    let mut order = [0usize; MAX_PE_RUNTIME_FUNCTIONS];
    for (index, function) in runtime_functions.iter().enumerate() {
        let begin = resolve_symbol(inputs, &linked.layouts, function.begin_symbol)?
            .checked_add(function.begin_offset)
            .and_then(|offset| offset.checked_add(TEXT_RVA))
            .ok_or(LinkerError::OffsetOverflow)?;
        let end = resolve_symbol(inputs, &linked.layouts, function.end_symbol)?
            .checked_add(function.end_offset)
            .and_then(|offset| offset.checked_add(TEXT_RVA))
            .ok_or(LinkerError::OffsetOverflow)?;
        if end <= begin {
            return Err(LinkerError::InvalidRelocationOffset);
        }
        begin_rvas[index] = to_u32_link(begin)?;
        end_rvas[index] = to_u32_link(end)?;
        order[index] = index;
        copy_at(
            &mut bytes,
            readonly_raw + unwind_offsets[index],
            function.unwind_info,
        )?;
    }
    for index in 1..runtime_functions.len() {
        let selected = order[index];
        let mut position = index;
        while position > 0 && begin_rvas[order[position - 1]] > begin_rvas[selected] {
            order[position] = order[position - 1];
            position -= 1;
        }
        order[position] = selected;
    }
    for (record, function_index) in order[..runtime_functions.len()].iter().enumerate() {
        let output = readonly_raw + pdata_offset + record * 12;
        patch_u32(&mut bytes, output, begin_rvas[*function_index])?;
        patch_u32(&mut bytes, output + 4, end_rvas[*function_index])?;
        patch_u32(
            &mut bytes,
            output + 8,
            to_u32_link(readonly_rva + unwind_offsets[*function_index])?,
        )?;
    }
    for (index, data) in writable_data.iter().enumerate() {
        let output = writable_raw + writable_offsets[index];
        copy_at(&mut bytes, output, data.bytes)?;
        for relocation in data.relocations {
            let target_rva = resolve_readonly_symbol(
                inputs,
                &linked.layouts,
                linked.readonly_offset,
                readonly_rva,
                relocation.target_readonly_owner,
                relocation.target_readonly_offset,
            )?;
            let target = IMAGE_BASE
                .checked_add(target_rva)
                .ok_or(LinkerError::OffsetOverflow)?;
            patch_u64(
                &mut bytes,
                output + relocation.offset,
                u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
        }
    }
    Ok(PeImage { bytes, length })
}

/// Links MRML fragments into a deterministic, fixed-address, import-free
/// x86-64 ELF executable with page-separated load permissions.
pub fn link_x86_64_elf_executable<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
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
    inputs: &[LinkInput<'_, '_, '_>],
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
        for (definition_index, definition) in input.additional_definitions.iter().enumerate() {
            validate_symbol(definition.symbol)?;
            if definition.text_offset > input.text.len() {
                return Err(LinkerError::InvalidRelocationOffset);
            }
            if definition.symbol == input.symbol
                || input.additional_definitions[..definition_index]
                    .iter()
                    .any(|earlier| earlier.symbol == definition.symbol)
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        relocation_count = relocation_count
            .checked_add(input.relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if relocation_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for definition in core::iter::once(LinkDefinition {
            symbol: input.symbol,
            text_offset: 0,
        })
        .chain(input.additional_definitions.iter().copied())
        {
            if inputs[..index]
                .iter()
                .any(|earlier| input_definition_offset(earlier, definition.symbol).is_some())
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        for relocation in input.relocations {
            match relocation.target {
                LinkRelocationTarget::Symbol(symbol)
                | LinkRelocationTarget::LocalSymbol(symbol) => validate_symbol(symbol)?,
                LinkRelocationTarget::InputText(offset) if offset > input.text.len() => {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                LinkRelocationTarget::InputText(_) => {}
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
                LinkRelocationTarget::Symbol(symbol)
                | LinkRelocationTarget::LocalSymbol(symbol) => {
                    resolve_symbol(inputs, &layouts, symbol)?
                }
                LinkRelocationTarget::InputText(offset) => layout
                    .text
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
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
        layouts,
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
    inputs: &[LinkInput<'_, '_, '_>],
    layouts: &[InputLayout; MAX_LINK_INPUTS],
    symbol: &str,
) -> Result<usize, LinkerError> {
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        if let Some(offset) = input_definition_offset(input, symbol) {
            return layout
                .text
                .checked_add(offset)
                .ok_or(LinkerError::OffsetOverflow);
        }
    }
    Err(LinkerError::UndefinedSymbol)
}

fn resolve_readonly_symbol(
    inputs: &[LinkInput<'_, '_, '_>],
    layouts: &[InputLayout; MAX_LINK_INPUTS],
    linked_readonly_offset: usize,
    readonly_rva: usize,
    owner_symbol: &str,
    data_offset: usize,
) -> Result<usize, LinkerError> {
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        if input_definition_offset(input, owner_symbol).is_some() {
            if data_offset > input.readonly_data.len() {
                return Err(LinkerError::InvalidRelocationOffset);
            }
            return layout
                .readonly
                .checked_sub(linked_readonly_offset)
                .and_then(|offset| offset.checked_add(readonly_rva))
                .and_then(|offset| offset.checked_add(data_offset))
                .ok_or(LinkerError::OffsetOverflow);
        }
    }
    Err(LinkerError::UndefinedSymbol)
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

fn read_u64_coff(bytes: &[u8], offset: usize) -> Result<u64, LinkerError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
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

fn coff_section_name<'a>(
    raw: &'a [u8],
    object: &'a [u8],
    strings_offset: usize,
    strings_size: usize,
) -> Result<&'a str, LinkerError> {
    let raw_length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let raw = core::str::from_utf8(&raw[..raw_length]).map_err(|_| LinkerError::InvalidCoff)?;
    if let Some(offset) = raw.strip_prefix('/') {
        let offset =
            parse_archive_usize(offset.as_bytes()).map_err(|_| LinkerError::InvalidCoff)?;
        if offset < 4 || offset >= strings_size {
            return Err(LinkerError::InvalidCoff);
        }
        let start = strings_offset
            .checked_add(offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        let limit = strings_offset
            .checked_add(strings_size)
            .ok_or(LinkerError::OffsetOverflow)?;
        let tail = object.get(start..limit).ok_or(LinkerError::InvalidCoff)?;
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(LinkerError::InvalidCoff)?;
        return core::str::from_utf8(&tail[..length]).map_err(|_| LinkerError::InvalidCoff);
    }
    Ok(raw)
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
        MachineCode, X86_64PcRelativeRelocation, X86_64PcRelativeRelocationKind, emit_elf64_x86_64,
        emit_elf64_x86_64_with_readonly_data, emit_elf64_x86_64_with_relocation, emit_x86_64_coff,
        emit_x86_64_coff_with_relocation,
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

    fn two_fragment_coff() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 157];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&2u16.to_le_bytes());
        object[8..12].copy_from_slice(&117u32.to_le_bytes());
        object[12..16].copy_from_slice(&2u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&6u32.to_le_bytes());
        object[40..44].copy_from_slice(&100u32.to_le_bytes());
        object[44..48].copy_from_slice(&106u32.to_le_bytes());
        object[52..54].copy_from_slice(&1u16.to_le_bytes());
        object[60..67].copy_from_slice(b".text$b");
        object[76..80].copy_from_slice(&1u32.to_le_bytes());
        object[80..84].copy_from_slice(&116u32.to_le_bytes());

        object[100..106].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xc3]);
        object[106..110].copy_from_slice(&1u32.to_le_bytes());
        object[110..114].copy_from_slice(&1u32.to_le_bytes());
        object[114..116].copy_from_slice(&4u16.to_le_bytes());
        object[116] = 0xc3;

        object[117..122].copy_from_slice(b"entry");
        object[129..131].copy_from_slice(&1i16.to_le_bytes());
        object[133] = 2;
        object[135..141].copy_from_slice(b"helper");
        object[147..149].copy_from_slice(&2i16.to_le_bytes());
        object[151] = 2;
        object[153..157].copy_from_slice(&4u32.to_le_bytes());
        object
    }

    fn two_fragment_coff_with_removed_metadata() -> std::vec::Vec<u8> {
        let original = two_fragment_coff();
        let mut object = std::vec![0u8; original.len() + 40];
        object[..100].copy_from_slice(&original[..100]);
        object[140..].copy_from_slice(&original[100..]);
        object[2..4].copy_from_slice(&3u16.to_le_bytes());
        object[8..12].copy_from_slice(&157u32.to_le_bytes());
        object[40..44].copy_from_slice(&140u32.to_le_bytes());
        object[44..48].copy_from_slice(&146u32.to_le_bytes());
        object[80..84].copy_from_slice(&156u32.to_le_bytes());
        object[100..108].copy_from_slice(b".llvmcmd");
        object[120..124].copy_from_slice(&156u32.to_le_bytes());
        object[136..140].copy_from_slice(&0xc010_0800u32.to_le_bytes());
        object
    }

    fn coff_with_one_runtime_function() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 245];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&3u16.to_le_bytes());
        object[8..12].copy_from_slice(&187u32.to_le_bytes());
        object[12..16].copy_from_slice(&3u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&1u32.to_le_bytes());
        object[40..44].copy_from_slice(&140u32.to_le_bytes());
        object[60..68].copy_from_slice(b".xdata$a");
        object[76..80].copy_from_slice(&4u32.to_le_bytes());
        object[80..84].copy_from_slice(&141u32.to_le_bytes());
        object[100..108].copy_from_slice(b".pdata$a");
        object[116..120].copy_from_slice(&12u32.to_le_bytes());
        object[120..124].copy_from_slice(&145u32.to_le_bytes());
        object[124..128].copy_from_slice(&157u32.to_le_bytes());
        object[132..134].copy_from_slice(&3u16.to_le_bytes());

        object[140] = 0xc3;
        object[141..145].copy_from_slice(&[1, 2, 3, 4]);
        object[149..153].copy_from_slice(&1u32.to_le_bytes());
        for (record, field) in [0u32, 4, 8].into_iter().enumerate() {
            let offset = 157 + record * 10;
            object[offset..offset + 4].copy_from_slice(&field.to_le_bytes());
            object[offset + 4..offset + 8]
                .copy_from_slice(&(if record == 2 { 2u32 } else { 0u32 }).to_le_bytes());
            object[offset + 8..offset + 10].copy_from_slice(&3u16.to_le_bytes());
        }

        object[187..194].copy_from_slice(b".text$a");
        object[199..201].copy_from_slice(&1i16.to_le_bytes());
        object[203] = 3;
        object[205..210].copy_from_slice(b"entry");
        object[217..219].copy_from_slice(&1i16.to_le_bytes());
        object[221] = 2;
        object[223..231].copy_from_slice(b".xdata$a");
        object[235..237].copy_from_slice(&2i16.to_le_bytes());
        object[239] = 3;
        object[241..245].copy_from_slice(&4u32.to_le_bytes());
        object
    }

    fn coff_with_readonly_and_writable_data() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 203];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&3u16.to_le_bytes());
        object[8..12].copy_from_slice(&163u32.to_le_bytes());
        object[12..16].copy_from_slice(&2u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&1u32.to_le_bytes());
        object[40..44].copy_from_slice(&140u32.to_le_bytes());
        object[56..60].copy_from_slice(&0x6050_1020u32.to_le_bytes());
        object[60..68].copy_from_slice(b".rdata$a");
        object[76..80].copy_from_slice(&4u32.to_le_bytes());
        object[80..84].copy_from_slice(&141u32.to_le_bytes());
        object[96..100].copy_from_slice(&0x4040_1040u32.to_le_bytes());
        object[100..107].copy_from_slice(b".data$a");
        object[116..120].copy_from_slice(&8u32.to_le_bytes());
        object[120..124].copy_from_slice(&145u32.to_le_bytes());
        object[124..128].copy_from_slice(&153u32.to_le_bytes());
        object[132..134].copy_from_slice(&1u16.to_le_bytes());
        object[136..140].copy_from_slice(&0xc040_1040u32.to_le_bytes());

        object[140] = 0xc3;
        object[141..145].copy_from_slice(&42u32.to_le_bytes());
        object[153 + 4..153 + 8].copy_from_slice(&1u32.to_le_bytes());
        object[153 + 8..153 + 10].copy_from_slice(&1u16.to_le_bytes());

        object[163..168].copy_from_slice(b"entry");
        object[175..177].copy_from_slice(&1i16.to_le_bytes());
        object[179] = 2;
        object[181..186].copy_from_slice(b"VALUE");
        object[193..195].copy_from_slice(&2i16.to_le_bytes());
        object[197] = 2;
        object[199..203].copy_from_slice(&4u32.to_le_bytes());
        object
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
        let mut bsd_index = b"__.SYMDEF SORTED".to_vec();
        bsd_index.extend_from_slice(b"bsd-index");
        append_archive_member(&mut archive, "#1/16", &bsd_index);
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
            decode_unix_archive(b"!<thin>\n"),
            Err(LinkerError::UnsupportedArchive)
        );
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
    fn bounds_archive_member_count() {
        let mut archive = b"!<arch>\n".to_vec();
        for _ in 0..=MAX_ARCHIVE_MEMBERS {
            append_archive_member(&mut archive, "member.o/", b"");
        }
        assert_eq!(
            decode_unix_archive(&archive),
            Err(LinkerError::TooManyArchiveMembers)
        );
    }

    #[test]
    fn selects_only_transitively_needed_archive_members() {
        let entry_relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("middle"),
            addend: -4,
        }];
        let middle_relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("leaf"),
            addend: -4,
        }];
        let inputs = [
            LinkInput {
                symbol: "entry",
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &entry_relocation,
            },
            LinkInput {
                symbol: "unused",
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "middle",
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &middle_relocation,
            },
            LinkInput {
                symbol: "leaf",
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &[],
            },
        ];

        let selection =
            select_static_link_inputs(&inputs, &[false, true, true, true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0, 2, 3]);
    }

    #[test]
    fn selects_an_archive_entry_and_ignores_later_duplicate_members() {
        let inputs = [
            LinkInput {
                symbol: "entry",
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "entry",
                additional_definitions: &[],
                text: &[0xcc],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "unused",
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
        ];

        let selection = select_static_link_inputs(&inputs, &[true, true, true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0]);
    }

    #[test]
    fn ordered_archive_selection_does_not_revisit_earlier_archives() {
        let relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("helper"),
            addend: -4,
        }];
        let helper = LinkInput {
            symbol: "helper",
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &[],
        };
        let entry = LinkInput {
            symbol: "entry",
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &relocation,
        };

        let earlier =
            select_ordered_static_link_inputs(&[helper, entry], &[1, 0], "entry").unwrap();
        assert_eq!(earlier.indices(), &[1]);
        let later = select_ordered_static_link_inputs(&[entry, helper], &[0, 1], "entry").unwrap();
        assert_eq!(later.indices(), &[0, 1]);
    }

    #[test]
    fn ordered_archive_selection_extracts_all_fragments_of_one_member() {
        let call_helper = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("helper"),
            addend: 0,
        }];
        let entry = LinkInput {
            symbol: "entry",
            additional_definitions: &[],
            text: &[0, 0, 0, 0],
            readonly_data: &[],
            relocations: &call_helper,
        };
        let helper = LinkInput {
            symbol: "helper",
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let unwind_fragment = LinkInput {
            symbol: "helper.unwind",
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };

        let selection = select_ordered_static_link_members(
            &[entry, helper, unwind_fragment],
            &[0, 1, 1],
            &[0, 7, 7],
            "entry",
        )
        .unwrap();
        assert_eq!(selection.indices(), &[0, 1, 2]);
    }

    #[test]
    fn ordered_archive_member_identity_fails_closed_outside_archives() {
        let input = LinkInput {
            symbol: "entry",
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        assert_eq!(
            select_ordered_static_link_members(&[input], &[0], &[1], "entry"),
            Err(LinkerError::InvalidArchive)
        );
        assert_eq!(
            select_ordered_static_link_members(&[input], &[1], &[0], "entry"),
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
                additional_definitions: &[],
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"A",
                relocations: &[to_helper],
            },
            LinkInput {
                symbol: "helper",
                additional_definitions: &[],
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
    fn resolves_multiple_definitions_at_checked_text_offsets() {
        let definitions = [LinkDefinition {
            symbol: "secondary",
            text_offset: 1,
        }];
        let input = LinkInput {
            symbol: "primary",
            additional_definitions: &definitions,
            text: &[0xc3, 0xb8, 42, 0, 0, 0, 0xc3],
            readonly_data: &[],
            relocations: &[],
        };

        let linked = link_x86_64_static::<32>(&[input], "secondary").unwrap();
        assert_eq!(linked.entry_offset(), 1);
        assert_eq!(&linked.bytes()[1..7], &[0xb8, 42, 0, 0, 0, 0xc3]);

        let invalid = LinkInput {
            additional_definitions: &[LinkDefinition {
                symbol: "outside",
                text_offset: 8,
            }],
            ..input
        };
        assert_eq!(
            link_x86_64_static::<32>(&[invalid], "primary"),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn archive_selection_matches_additional_definitions() {
        let definitions = [LinkDefinition {
            symbol: "entry",
            text_offset: 1,
        }];
        let input = LinkInput {
            symbol: "other",
            additional_definitions: &definitions,
            text: &[0xc3, 0xc3],
            readonly_data: &[],
            relocations: &[],
        };

        let selection = select_static_link_inputs(&[input], &[true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0]);
    }

    #[test]
    fn rejects_ambiguous_missing_and_out_of_bounds_inputs() {
        let plain = LinkInput {
            symbol: "same",
            additional_definitions: &[],
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
        use crate::{X86_64ReadonlyRelocation, emit_x86_64_coff_with_readonly_data};

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

        let mut comdat = object.bytes().to_vec();
        comdat[60..68].copy_from_slice(b".rdata$x");
        let mut comdat_storage = storage;
        let decoded_comdat = decode_x86_64_coff(&comdat, &mut comdat_storage).unwrap();
        assert_eq!(decoded_comdat.readonly_data, b"hello");
        assert_eq!(
            decoded_comdat.relocations[0].target,
            LinkRelocationTarget::ReadonlyData(1)
        );
    }

    #[test]
    fn decodes_multiple_coff_text_definitions_with_offsets() {
        let code = MachineCode::<8>::from_bytes_for_test(&[0xe8, 0, 0, 0, 0, 0xc3, 0xc3]);
        let object = emit_x86_64_coff_with_relocation::<256, 8>(
            "primary",
            &code,
            X86_64PcRelativeRelocation {
                offset: 1,
                symbol: "second",
                kind: X86_64PcRelativeRelocationKind::Branch,
            },
        )
        .unwrap();
        let mut bytes = object.bytes().to_vec();
        let symbol_offset = usize::try_from(read_u32(&bytes, 8).unwrap()).unwrap();
        assert_eq!(read_u32(&bytes, 12).unwrap(), 2);
        bytes[symbol_offset + 18 + 8..symbol_offset + 18 + 12].copy_from_slice(&6u32.to_le_bytes());
        bytes[symbol_offset + 18 + 12..symbol_offset + 18 + 14]
            .copy_from_slice(&1i16.to_le_bytes());

        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        let decoded =
            decode_x86_64_coff_with_definitions(&bytes, &mut relocations, &mut definitions)
                .unwrap();
        assert_eq!(
            decoded.additional_definitions,
            &[LinkDefinition {
                symbol: "second",
                text_offset: 6,
            }]
        );
        assert_eq!(
            decoded.relocations,
            &[LinkRelocation {
                offset: 1,
                target: LinkRelocationTarget::InputText(6),
                addend: -4,
            }]
        );
        assert_eq!(
            link_x86_64_static::<32>(&[decoded], "second")
                .unwrap()
                .entry_offset(),
            6
        );

        let mut legacy_relocations = relocations;
        assert_eq!(
            decode_x86_64_coff(&bytes, &mut legacy_relocations),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn decodes_bounded_coff_text_fragments_without_losing_object_identity() {
        let object = two_fragment_coff();
        assert_eq!(x86_64_coff_text_fragment_count(&object), Ok(2));
        assert_eq!(x86_64_coff_unwind_section_count(&object), Ok(0));

        let mut first_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut second_relocations = first_relocations;
        let mut first_definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        let mut second_definitions = first_definitions;
        let first = decode_x86_64_coff_text_fragment(
            &object,
            0,
            &mut first_relocations,
            &mut first_definitions,
        )
        .unwrap();
        let second = decode_x86_64_coff_text_fragment(
            &object,
            1,
            &mut second_relocations,
            &mut second_definitions,
        )
        .unwrap();
        assert_eq!(first.symbol, "entry");
        assert_eq!(second.symbol, "helper");
        assert_eq!(
            first.relocations,
            &[LinkRelocation {
                offset: 1,
                target: LinkRelocationTarget::Symbol("helper"),
                addend: -4,
            }]
        );
        assert_eq!(
            link_x86_64_static::<64>(&[first, second], "entry")
                .unwrap()
                .bytes()[16],
            0xc3
        );

        let mut legacy_relocations = first_relocations;
        let mut legacy_definitions = first_definitions;
        assert_eq!(
            decode_x86_64_coff_with_definitions(
                &object,
                &mut legacy_relocations,
                &mut legacy_definitions,
            ),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn resolves_static_coff_text_targets_without_exporting_them_for_selection() {
        let mut object = two_fragment_coff();
        object[151] = 3;
        let mut first_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut second_relocations = first_relocations;
        let mut first_definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        let mut second_definitions = first_definitions;
        let first = decode_x86_64_coff_text_fragment(
            &object,
            0,
            &mut first_relocations,
            &mut first_definitions,
        )
        .unwrap();
        let second = decode_x86_64_coff_text_fragment(
            &object,
            1,
            &mut second_relocations,
            &mut second_definitions,
        )
        .unwrap();
        assert_eq!(second.symbol, ".text$b");
        assert_eq!(
            first.relocations,
            &[LinkRelocation {
                offset: 1,
                target: LinkRelocationTarget::LocalSymbol(".text$b"),
                addend: -4,
            }]
        );
        assert_eq!(
            select_ordered_static_link_members(&[first, second], &[0, 1], &[0, 1], "entry")
                .unwrap()
                .indices(),
            &[0]
        );
        assert_eq!(
            link_x86_64_static::<64>(&[first, second], "entry")
                .unwrap()
                .bytes()[16],
            0xc3
        );
    }

    #[test]
    fn ignores_only_relocation_free_coff_link_remove_metadata() {
        let object = two_fragment_coff_with_removed_metadata();
        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        assert!(
            decode_x86_64_coff_text_fragment(&object, 0, &mut relocations, &mut definitions,)
                .is_ok()
        );

        let mut retained = object.clone();
        retained[136..140].copy_from_slice(&0xc010_0000u32.to_le_bytes());
        let mut retained_relocations = relocations;
        let mut retained_definitions = definitions;
        assert_eq!(
            decode_x86_64_coff_text_fragment(
                &retained,
                0,
                &mut retained_relocations,
                &mut retained_definitions,
            ),
            Err(LinkerError::UnsupportedCoff)
        );
        let mut relocated = object.clone();
        relocated[132..134].copy_from_slice(&1u16.to_le_bytes());
        let mut relocated_relocations = relocations;
        let mut relocated_definitions = definitions;
        assert_eq!(
            decode_x86_64_coff_text_fragment(
                &relocated,
                0,
                &mut relocated_relocations,
                &mut relocated_definitions,
            ),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn decodes_typed_addr32nb_runtime_function_records() {
        let object = coff_with_one_runtime_function();
        assert_eq!(x86_64_coff_text_fragment_count(&object), Ok(1));
        assert_eq!(x86_64_coff_unwind_section_count(&object), Ok(2));
        let mut storage = [PeRuntimeFunction {
            begin_symbol: "unused",
            begin_offset: 0,
            end_symbol: "unused",
            end_offset: 0,
            unwind_info: &[],
        }; MAX_PE_RUNTIME_FUNCTIONS];
        let records = decode_x86_64_coff_runtime_functions(&object, &mut storage).unwrap();
        assert_eq!(
            records,
            &[PeRuntimeFunction {
                begin_symbol: "entry",
                begin_offset: 0,
                end_symbol: "entry",
                end_offset: 1,
                unwind_info: &[1, 2, 3, 4],
            }]
        );

        let mut invalid = object.clone();
        invalid[157 + 8..157 + 10].copy_from_slice(&4u16.to_le_bytes());
        let mut invalid_storage = [PeRuntimeFunction {
            begin_symbol: "unused",
            begin_offset: 0,
            end_symbol: "unused",
            end_offset: 0,
            unwind_info: &[],
        }; MAX_PE_RUNTIME_FUNCTIONS];
        assert_eq!(
            decode_x86_64_coff_runtime_functions(&invalid, &mut invalid_storage),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn decodes_typed_addr64_writable_coff_data() {
        let object = coff_with_readonly_and_writable_data();
        assert_eq!(x86_64_coff_writable_section_count(&object), Ok(1));
        let mut storage = [PeWritableRelocation {
            offset: 0,
            target_readonly_owner: "unused",
            target_readonly_offset: 0,
        }; MAX_LINK_RELOCATIONS];
        let writable = decode_x86_64_coff_writable_data(&object, "entry", &mut storage)
            .unwrap()
            .unwrap();
        assert_eq!(writable.bytes, &[0; 8]);
        assert_eq!(
            writable.relocations,
            &[PeWritableRelocation {
                offset: 0,
                target_readonly_owner: "entry",
                target_readonly_offset: 0,
            }]
        );
        let mut fragment_storage = [PeWritableRelocation {
            offset: 0,
            target_readonly_owner: "unused",
            target_readonly_offset: 0,
        }; MAX_LINK_RELOCATIONS];
        let fragment =
            decode_x86_64_coff_writable_data_fragment(&object, 0, "entry", &mut fragment_storage)
                .unwrap();
        assert_eq!(fragment, writable);
        let mut missing_storage = [PeWritableRelocation {
            offset: 0,
            target_readonly_owner: "unused",
            target_readonly_offset: 0,
        }; MAX_LINK_RELOCATIONS];
        assert_eq!(
            decode_x86_64_coff_writable_data_fragment(&object, 1, "entry", &mut missing_storage,),
            Err(LinkerError::InvalidCoff)
        );

        let mut invalid = object.clone();
        invalid[153 + 8..153 + 10].copy_from_slice(&4u16.to_le_bytes());
        let mut invalid_storage = storage;
        assert_eq!(
            decode_x86_64_coff_writable_data(&invalid, "entry", &mut invalid_storage),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn decodes_one_long_named_coff_comdat_text_section() {
        let code = MachineCode::<8>::from_bytes_for_test(&[0xc3]);
        let object = emit_x86_64_coff::<192, 8>("entry", &code).unwrap();
        let mut bytes = object.bytes().to_vec();
        bytes[20..28].fill(0);
        bytes[20..22].copy_from_slice(b"/4");
        let symbol_offset = usize::try_from(read_u32(&bytes, 8).unwrap()).unwrap();
        let symbol_count = usize::try_from(read_u32(&bytes, 12).unwrap()).unwrap();
        let strings_offset = symbol_offset + symbol_count * 18;
        bytes.extend_from_slice(b".text$entry\0");
        bytes[strings_offset..strings_offset + 4].copy_from_slice(&16u32.to_le_bytes());

        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        let decoded =
            decode_x86_64_coff_with_definitions(&bytes, &mut relocations, &mut definitions)
                .unwrap();
        assert_eq!(decoded.symbol, "entry");
        assert_eq!(decoded.text, &[0xc3]);
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
            additional_definitions: &[],
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

    #[test]
    fn emits_sorted_pe_runtime_functions_and_readonly_unwind_bytes() {
        let inputs = [
            LinkInput {
                symbol: "entry",
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "helper",
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
        ];
        let runtime_functions = [
            PeRuntimeFunction {
                begin_symbol: "helper",
                begin_offset: 0,
                end_symbol: "helper",
                end_offset: 1,
                unwind_info: &[1, 2, 3, 4],
            },
            PeRuntimeFunction {
                begin_symbol: "entry",
                begin_offset: 0,
                end_symbol: "entry",
                end_offset: 1,
                unwind_info: &[5, 6, 7, 8],
            },
        ];
        let pe =
            link_x86_64_pe_with_unwind::<2048, 8192>(&inputs, "entry", &runtime_functions).unwrap();
        assert_eq!(read_u32(pe.bytes(), 0x120).unwrap(), 0x2008);
        assert_eq!(read_u32(pe.bytes(), 0x124).unwrap(), 24);
        assert_eq!(&pe.bytes()[0x400..0x408], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(read_u32(pe.bytes(), 0x408).unwrap(), 0x1000);
        assert_eq!(read_u32(pe.bytes(), 0x40c).unwrap(), 0x1001);
        assert_eq!(read_u32(pe.bytes(), 0x410).unwrap(), 0x2004);
        assert_eq!(read_u32(pe.bytes(), 0x414).unwrap(), 0x1010);
        assert_eq!(read_u32(pe.bytes(), 0x418).unwrap(), 0x1011);
        assert_eq!(read_u32(pe.bytes(), 0x41c).unwrap(), 0x2000);
    }

    #[test]
    fn emits_rw_nx_pe_data_and_resolves_fixed_addr64_targets() {
        let input = LinkInput {
            symbol: "entry",
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &42u64.to_le_bytes(),
            relocations: &[],
        };
        let relocation = PeWritableRelocation {
            offset: 0,
            target_readonly_owner: "entry",
            target_readonly_offset: 0,
        };
        let writable = PeWritableData {
            bytes: &[0; 8],
            relocations: &[relocation],
        };
        let pe =
            link_x86_64_pe_with_data_and_unwind::<2048, 8192>(&[input], "entry", &[], &[writable])
                .unwrap();
        assert_eq!(read_u16(pe.bytes(), 0x86).unwrap(), 3);
        assert_eq!(&pe.bytes()[0x1d8..0x1e0], b".data\0\0\0");
        assert_eq!(read_u32(pe.bytes(), 0x1d8 + 12).unwrap(), 0x3000);
        assert_eq!(read_u32(pe.bytes(), 0x1d8 + 36).unwrap(), 0xc000_0040);
        assert_eq!(
            u64::from_le_bytes(pe.bytes()[0x600..0x608].try_into().unwrap()),
            0x0000_0001_4000_2000
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn generated_pe_executes_on_the_controlled_windows_host() {
        let input = LinkInput {
            symbol: "entry",
            additional_definitions: &[],
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
            additional_definitions: &[],
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
    fn decodes_multiple_elf_text_definitions_and_internal_calls() {
        let code = MachineCode::<8>::from_bytes_for_test(&[0xe8, 0, 0, 0, 0, 0xc3, 0xc3]);
        let object = emit_elf64_x86_64_with_relocation::<768, 8>(
            "primary",
            &code,
            X86_64PcRelativeRelocation {
                offset: 1,
                symbol: "second",
                kind: X86_64PcRelativeRelocationKind::Branch,
            },
        )
        .unwrap();
        let mut bytes = object.bytes().to_vec();
        let section_offset = to_usize_elf(read_u64_elf(&bytes, 40).unwrap()).unwrap();
        let symbols_header = elf_section_header(section_offset, 6, 3).unwrap();
        let symbols_offset =
            to_usize_elf(read_u64_elf(&bytes, symbols_header + 24).unwrap()).unwrap();
        let second_offset = symbols_offset + 2 * 24;
        bytes[second_offset + 6..second_offset + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[second_offset + 8..second_offset + 16].copy_from_slice(&6u64.to_le_bytes());

        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            text_offset: 0,
        }; MAX_LINK_DEFINITIONS];
        let decoded =
            decode_x86_64_elf_with_definitions(&bytes, &mut relocations, &mut definitions).unwrap();
        assert_eq!(
            decoded.additional_definitions,
            &[LinkDefinition {
                symbol: "second",
                text_offset: 6,
            }]
        );
        assert_eq!(
            decoded.relocations,
            &[LinkRelocation {
                offset: 1,
                target: LinkRelocationTarget::InputText(6),
                addend: -4,
            }]
        );
        assert_eq!(
            link_x86_64_static::<32>(&[decoded], "second")
                .unwrap()
                .entry_offset(),
            6
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
            additional_definitions: &[],
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
            additional_definitions: &[],
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
