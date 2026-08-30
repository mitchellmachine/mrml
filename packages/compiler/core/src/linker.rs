//! Bounded, deterministic x86-64 static-link planning and relocation.
//!
//! The passes deliberately have no shared mutable work between inputs until the
//! final copy/relocation pass. A hosted driver can therefore parallelize input
//! validation and relocation scanning later without changing link semantics.

pub const MAX_LINK_INPUTS: usize = 256;
/// Aggregate decoded code/read-only fragments retained after bounded object
/// expansion. Each COFF object remains independently capped at 4,096 sections;
/// the exact ORACLE-0003 `std` plus `gimli` path reaches 5,701 fragments across
/// two selected objects. Hosted decode arenas allocate only the measured count.
pub const MAX_LINK_FRAGMENTS: usize = 8192;
/// Pinned ORACLE-0003 Windows `std` peaks at 305 relocations in one text
/// fragment. Keep a power-of-two per-fragment arena that admits that exact
/// family while the aggregate selected-relocation bound remains independent.
pub const MAX_LINK_RELOCATIONS: usize = 512;
/// Aggregate relocations across retained fragments do not share one arena.
pub const MAX_LINK_TOTAL_RELOCATIONS: usize = MAX_LINK_FRAGMENTS;
pub const MAX_LINK_DEFINITIONS: usize = 256;
/// Object-wide PE read-only fixups are separate from per-fragment code arenas.
pub const MAX_PE_READONLY_RELOCATIONS: usize = MAX_LINK_FRAGMENTS;
/// Runtime metadata is independently bounded but must cover every retained
/// code fragment from an atomically selected COFF archive member.
pub const MAX_PE_RUNTIME_FUNCTIONS: usize = MAX_LINK_FRAGMENTS;
/// Ordinary members that may be indexed without making every member a link
/// input. Pinned ORACLE-0003 self-contained `ntdll` peaks at 2,341 members.
pub const MAX_ARCHIVE_MEMBERS: usize = 4096;
/// Pinned ORACLE-0003 `ntdll` peaks at 4,673 indexed symbols.
pub const MAX_ARCHIVE_SYMBOLS: usize = 8192;
/// Pinned ORACLE-0002 Windows archives peak at 3,834 sections in one `std`
/// member. Keep one power-of-two bounded table that admits that exact family.
const MAX_COFF_SECTIONS: usize = 4096;
const COFF_SECTION_SET_WORDS: usize = (MAX_COFF_SECTIONS + 64) / 64;
const MAX_ELF_SECTIONS: usize = 2048;
const MAX_ELF_COMDAT_GROUPS: usize = 4096;

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
    InvalidCoffAssociation,
    UnsupportedCoffSection,
    UnsupportedCoffTls,
    UnsupportedCoffSymbol,
    UnsupportedCoffRelocation,
    UnsupportedCoffRelocationTarget,
    UnsupportedCoffReadonlyLayout,
    UnsupportedCoff,
    InvalidElf,
    UnsupportedElf,
    InvalidArchive,
    UnsupportedArchive,
    TooManyArchiveMembers,
    TooManyArchiveSymbols,
    TooManyCoffSections,
    TooManyElfSections,
    TooManyElfComdatGroups,
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
            Self::InvalidCoffAssociation => "invalid COFF COMDAT association",
            Self::UnsupportedCoffSection => "unsupported COFF section",
            Self::UnsupportedCoffTls => "unsupported COFF TLS section",
            Self::UnsupportedCoffSymbol => "unsupported COFF symbol",
            Self::UnsupportedCoffRelocation => "unsupported COFF relocation",
            Self::UnsupportedCoffRelocationTarget => "unsupported COFF relocation target",
            Self::UnsupportedCoffReadonlyLayout => {
                "unsupported discontiguous COFF read-only layout"
            }
            Self::UnsupportedCoff => "unsupported COFF feature",
            Self::InvalidElf => "invalid bounded ELF64 input",
            Self::UnsupportedElf => "unsupported ELF64 feature",
            Self::InvalidArchive => "invalid Unix archive input",
            Self::UnsupportedArchive => "unsupported Unix archive feature",
            Self::TooManyArchiveMembers => "archive member capacity exceeded",
            Self::TooManyArchiveSymbols => "archive symbol-index capacity exceeded",
            Self::TooManyCoffSections => "COFF section capacity exceeded",
            Self::TooManyElfSections => "selected ELF section capacity exceeded",
            Self::TooManyElfComdatGroups => "ELF COMDAT group capacity exceeded",
        };
        formatter.write_str(message)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfLinkSelectionError<'a> {
    pub kind: LinkerError,
    pub symbol: Option<&'a str>,
}

impl core::fmt::Display for ElfLinkSelectionError<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.kind.fmt(formatter)?;
        if let Some(symbol) = self.symbol {
            write!(formatter, ": {symbol}")?;
        }
        Ok(())
    }
}

impl<'a> From<LinkerError> for ElfLinkSelectionError<'a> {
    fn from(kind: LinkerError) -> Self {
        Self { kind, symbol: None }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveMember<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
    /// Thin archives name an external file instead of storing its bytes.
    pub external: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveSymbol<'a> {
    pub symbol: &'a str,
    pub member_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveMembers<'a> {
    members: [ArchiveMember<'a>; MAX_ARCHIVE_MEMBERS],
    member_offsets: [usize; MAX_ARCHIVE_MEMBERS],
    length: usize,
    symbols: [ArchiveSymbol<'a>; MAX_ARCHIVE_SYMBOLS],
    symbol_length: usize,
}

impl<'a> ArchiveMembers<'a> {
    pub fn members(&self) -> &[ArchiveMember<'a>] {
        &self.members[..self.length]
    }

    pub fn symbols(&self) -> &[ArchiveSymbol<'a>] {
        &self.symbols[..self.symbol_length]
    }

    pub fn member_for_symbol(&self, symbol: &str) -> Option<&ArchiveMember<'a>> {
        self.symbols().iter().find_map(|entry| {
            (entry.symbol == symbol)
                .then(|| self.members.get(entry.member_index))
                .flatten()
        })
    }
}

/// Decodes ordinary Unix `ar`, GNU long-name, and BSD extended-name members.
/// Archive symbol indexes are metadata and are skipped; member selection remains
/// a separate linker pass.
pub fn decode_unix_archive(archive: &[u8]) -> Result<ArchiveMembers<'_>, LinkerError> {
    let thin = archive.get(..8) == Some(b"!<thin>\n");
    if !thin && archive.get(..8) != Some(b"!<arch>\n") {
        return Err(LinkerError::InvalidArchive);
    }
    let empty = ArchiveMember {
        name: "",
        bytes: &archive[0..0],
        external: false,
    };
    let empty_symbol = ArchiveSymbol {
        symbol: "",
        member_index: 0,
    };
    let mut decoded = ArchiveMembers {
        members: [empty; MAX_ARCHIVE_MEMBERS],
        member_offsets: [0; MAX_ARCHIVE_MEMBERS],
        length: 0,
        symbols: [empty_symbol; MAX_ARCHIVE_SYMBOLS],
        symbol_length: 0,
    };
    let mut string_table = None;
    let mut gnu_index = None;
    let mut coff_index = None;
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
        let raw_name = trim_archive_field(header.get(..16).ok_or(LinkerError::InvalidArchive)?)?;
        if thin && raw_name.starts_with("#1/") {
            return Err(LinkerError::UnsupportedArchive);
        }
        let stored_in_archive = !thin
            || raw_name == "//"
            || raw_name == "/"
            || raw_name == "/SYM64/"
            || raw_name.starts_with("__.SYMDEF");
        let stored_end = header_end
            .checked_add(if stored_in_archive { stored_size } else { 0 })
            .ok_or(LinkerError::OffsetOverflow)?;
        let stored = archive
            .get(header_end..stored_end)
            .ok_or(LinkerError::InvalidArchive)?;

        if raw_name == "//" {
            string_table = Some(stored);
        } else if raw_name == "/" || raw_name == "/SYM64/" {
            if gnu_index.is_none() {
                gnu_index = Some((stored, raw_name == "/SYM64/"));
            } else if raw_name == "/" && coff_index.replace(stored).is_none() {
                // Microsoft COFF libraries carry a redundant second linker
                // member after the ordinary big-endian archive index.
            } else {
                return Err(LinkerError::InvalidArchive);
            }
        } else if raw_name != "/" && raw_name != "/SYM64/" && !raw_name.starts_with("__.SYMDEF") {
            let (name, bytes) = decode_archive_member(raw_name, stored, string_table)?;
            if !name.starts_with("__.SYMDEF") {
                if thin {
                    validate_thin_archive_member_path(name)?;
                }
                if decoded.length == MAX_ARCHIVE_MEMBERS {
                    return Err(LinkerError::TooManyArchiveMembers);
                }
                decoded.members[decoded.length] = ArchiveMember {
                    name,
                    bytes,
                    external: thin,
                };
                decoded.member_offsets[decoded.length] = cursor;
                decoded.length += 1;
            }
        }

        cursor = stored_end
            .checked_add(if stored_in_archive {
                stored_size & 1
            } else {
                0
            })
            .ok_or(LinkerError::OffsetOverflow)?;
        if cursor > archive.len() {
            return Err(LinkerError::InvalidArchive);
        }
    }
    if let Some((index, wide)) = gnu_index {
        decoded.symbol_length = decode_gnu_archive_index(
            index,
            wide,
            &decoded.member_offsets[..decoded.length],
            &mut decoded.symbols,
        )?;
    }
    if let Some(index) = coff_index {
        validate_coff_archive_second_index(index, &decoded.member_offsets[..decoded.length])?;
    }
    Ok(decoded)
}

fn validate_coff_archive_second_index(
    index: &[u8],
    member_offsets: &[usize],
) -> Result<(), LinkerError> {
    let member_count = read_archive_le(index, 0, 4)?;
    if member_count != member_offsets.len() || member_count > MAX_ARCHIVE_MEMBERS {
        return Err(LinkerError::InvalidArchive);
    }
    let offsets_end = 4usize
        .checked_add(
            member_count
                .checked_mul(4)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    for (member, expected) in member_offsets.iter().copied().enumerate() {
        if read_archive_le(index, 4 + member * 4, 4)? != expected {
            return Err(LinkerError::InvalidArchive);
        }
    }
    let symbol_count = read_archive_le(index, offsets_end, 4)?;
    if symbol_count > MAX_ARCHIVE_SYMBOLS {
        return Err(LinkerError::TooManyArchiveSymbols);
    }
    let indices_start = offsets_end
        .checked_add(4)
        .ok_or(LinkerError::OffsetOverflow)?;
    let names_start = indices_start
        .checked_add(
            symbol_count
                .checked_mul(2)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    index
        .get(..names_start)
        .ok_or(LinkerError::InvalidArchive)?;
    let mut name_cursor = names_start;
    for symbol in 0..symbol_count {
        let member = read_archive_le(index, indices_start + symbol * 2, 2)?;
        if member == 0 || member > member_count {
            return Err(LinkerError::InvalidArchive);
        }
        let suffix = index
            .get(name_cursor..)
            .ok_or(LinkerError::InvalidArchive)?;
        let length = suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(LinkerError::InvalidArchive)?;
        let name = core::str::from_utf8(&suffix[..length])
            .map_err(|_| LinkerError::InvalidArchive)?;
        validate_symbol(name).map_err(|_| LinkerError::InvalidArchive)?;
        name_cursor = name_cursor
            .checked_add(length + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    // LLVM archive indexes may zero-pad the symbol names through the next
    // eight-byte boundary, including a four-byte pad after an empty index.
    // Keep that compatibility bounded and reject every nonzero trailing byte.
    let padding = index
        .get(name_cursor..)
        .ok_or(LinkerError::InvalidArchive)?;
    if padding.len() > 7 || padding.iter().any(|byte| *byte != 0) {
        return Err(LinkerError::InvalidArchive);
    }
    Ok(())
}

fn validate_thin_archive_member_path(path: &str) -> Result<(), LinkerError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
        || path
            .split(|character| character == '/' || character == '\\')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(LinkerError::InvalidArchive);
    }
    Ok(())
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
        let gnu_end = suffix.windows(2).position(|bytes| bytes == b"/\n");
        let coff_end = suffix.iter().position(|byte| *byte == 0);
        let end = match (gnu_end, coff_end) {
            (Some(gnu), Some(coff)) => core::cmp::min(gnu, coff),
            (Some(gnu), None) => gnu,
            (None, Some(coff)) => coff,
            (None, None) => return Err(LinkerError::InvalidArchive),
        };
        let name = core::str::from_utf8(&suffix[..end]).map_err(|_| LinkerError::InvalidArchive)?;
        return Ok((name, stored));
    }
    Ok((raw_name.strip_suffix('/').unwrap_or(raw_name), stored))
}

fn decode_gnu_archive_index<'a>(
    index: &'a [u8],
    wide: bool,
    member_offsets: &[usize],
    symbols: &mut [ArchiveSymbol<'a>; MAX_ARCHIVE_SYMBOLS],
) -> Result<usize, LinkerError> {
    let width = if wide { 8 } else { 4 };
    let count = read_archive_be(index, 0, width)?;
    if count > symbols.len() {
        return Err(LinkerError::TooManyArchiveSymbols);
    }
    let offsets_end = width
        .checked_add(
            count
                .checked_mul(width)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    index
        .get(..offsets_end)
        .ok_or(LinkerError::InvalidArchive)?;
    let mut name_cursor = offsets_end;
    for symbol_index in 0..count {
        let offset = read_archive_be(index, width + symbol_index * width, width)?;
        let member_index = member_offsets
            .iter()
            .position(|candidate| *candidate == offset)
            .ok_or(LinkerError::InvalidArchive)?;
        let suffix = index
            .get(name_cursor..)
            .ok_or(LinkerError::InvalidArchive)?;
        let length = suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(LinkerError::InvalidArchive)?;
        let name =
            core::str::from_utf8(&suffix[..length]).map_err(|_| LinkerError::InvalidArchive)?;
        validate_symbol(name).map_err(|_| LinkerError::InvalidArchive)?;
        symbols[symbol_index] = ArchiveSymbol {
            symbol: name,
            member_index,
        };
        name_cursor = name_cursor
            .checked_add(length + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    // LLVM uses the same bounded zero padding for ordinary big-endian symbol
    // indexes, notably four bytes after a zero-symbol index in tiny rlibs.
    let padding = index
        .get(name_cursor..)
        .ok_or(LinkerError::InvalidArchive)?;
    if padding.len() > 7 || padding.iter().any(|byte| *byte != 0) {
        return Err(LinkerError::InvalidArchive);
    }
    Ok(count)
}

fn read_archive_be(bytes: &[u8], offset: usize, width: usize) -> Result<usize, LinkerError> {
    let field = bytes
        .get(offset..offset + width)
        .ok_or(LinkerError::InvalidArchive)?;
    let mut value = 0usize;
    for byte in field {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(value)
}

fn read_archive_le(bytes: &[u8], offset: usize, width: usize) -> Result<usize, LinkerError> {
    let field = bytes
        .get(offset..offset + width)
        .ok_or(LinkerError::InvalidArchive)?;
    let mut value = 0usize;
    for byte in field.iter().rev() {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(value)
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
pub struct CoffSectionIdentity {
    object: u16,
    section: u16,
}

impl CoffSectionIdentity {
    pub fn new(object: u16, section: u16) -> Result<Self, LinkerError> {
        if object == 0 || section == 0 {
            return Err(LinkerError::InvalidCoff);
        }
        Ok(Self { object, section })
    }

    pub const fn object(self) -> u16 {
        self.object
    }

    pub const fn section(self) -> u16 {
        self.section
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRelocationTarget<'a> {
    Symbol(&'a str),
    /// A named dependency discovered outside text. It participates in archive
    /// selection and symbol validation but owns no text field to patch.
    RequiredSymbol(&'a str),
    /// A validated indirect call/jump through a GOT slot that can be relaxed
    /// only when the symbol resolves in this fixed static image.
    GotPcRelativeSymbol(&'a str),
    /// A COFF section-scoped code target. It participates in relocation
    /// resolution but never makes an archive member eligible for selection.
    LocalSymbol(&'a str),
    /// An exact non-global COFF section in one decoded source object.
    CoffSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
    /// A COFF object-local writable definition whose final RVA is assigned by
    /// the PE serializer after the generic text/read-only layout is frozen.
    PeWritableSymbol(&'a str),
    /// The address of one loader-populated PE import slot. The containing
    /// synthetic text input is the callable global thunk.
    PeImportAddress {
        library: &'a str,
        symbol: &'a str,
    },
    /// An exact selected COFF TLS section. PE TLS directory, template, index,
    /// and thread-lifecycle layout remain a later serializer gate.
    PeTlsSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
    InputText(usize),
    ReadonlyData(usize),
    /// A validated `mov reg, [rip + GOT]` whose fixed-image target is local
    /// read-only data and can therefore become `lea reg, [rip + data]`.
    GotPcRelativeReadonlyData(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkDefinitionTarget {
    Text(usize),
    ReadonlyData(usize),
    /// Defines an exact non-global COFF text section without inventing a name.
    CoffTextSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
    /// Defines an exact non-global COFF read-only section without inventing a name.
    CoffSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkDefinition<'a> {
    pub symbol: &'a str,
    pub target: LinkDefinitionTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInput<'data, 'relocations, 'definitions> {
    pub symbol: &'data str,
    pub symbol_target: LinkDefinitionTarget,
    pub additional_definitions: &'definitions [LinkDefinition<'data>],
    pub text: &'data [u8],
    pub readonly_data: &'data [u8],
    pub relocations: &'relocations [LinkRelocation<'data>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfUnwindRelocation {
    /// Offset of the four-byte PC-relative field within `.eh_frame`.
    pub offset: usize,
    /// Checked offset of the described function within this input's combined text.
    pub target_text_offset: usize,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfUnwindData<'data, 'relocations> {
    pub bytes: &'data [u8],
    pub relocations: &'relocations [ElfUnwindRelocation],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfWritableTarget {
    Initialized(usize),
    Zeroed(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfWritableReference {
    pub text_offset: usize,
    pub target: ElfWritableTarget,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfWritableAbsoluteTarget<'a> {
    Symbol(&'a str),
    InputText(usize),
    ReadonlyData(usize),
    Initialized(usize),
    Zeroed(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfWritableAbsoluteRelocation<'a> {
    pub offset: usize,
    pub target: ElfWritableAbsoluteTarget<'a>,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfWritableData<'data, 'relocations> {
    pub initialized: &'data [u8],
    pub initialized_alignment: usize,
    pub zeroed_size: usize,
    pub zeroed_alignment: usize,
    pub references: &'relocations [ElfWritableReference],
    pub absolute_relocations: &'relocations [ElfWritableAbsoluteRelocation<'data>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeRuntimeFunction<'a> {
    pub begin_symbol: &'a str,
    pub begin_identity: Option<CoffSectionIdentity>,
    pub begin_offset: usize,
    pub end_symbol: &'a str,
    pub end_identity: Option<CoffSectionIdentity>,
    pub end_offset: usize,
    pub unwind_info: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeWritableRelocationTarget<'a> {
    Readonly { owner: &'a str, offset: usize },
    CoffSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
    TextSymbol(&'a str),
    TlsSection {
        identity: CoffSectionIdentity,
        offset: usize,
    },
    WritableSymbol(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeWritableRelocation<'a> {
    pub offset: usize,
    pub target: PeWritableRelocationTarget<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeWritableComdatSelection {
    None,
    NoDuplicates,
    Any,
}

/// The bounded COFF duplicate-selection policy attached to one text section.
/// Selection values outside this deliberately small set fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoffTextComdatSelection {
    None,
    NoDuplicates,
    Any,
    SameSize,
    ExactMatch,
    Associative,
    Largest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffComdatSection {
    pub section_number: u16,
    pub selection: CoffTextComdatSelection,
    pub associated_section: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffComdatSections<'a> {
    object: &'a [u8],
    section_count: u16,
    len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffComdatSectionIter<'inventory, 'object> {
    inventory: &'inventory CoffComdatSections<'object>,
    next_section: u16,
    remaining: usize,
}

#[derive(Clone, Copy)]
struct CoffSectionSet {
    words: [u64; COFF_SECTION_SET_WORDS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffReadonlyLinkInput<'data, 'definitions> {
    pub input: LinkInput<'data, 'data, 'definitions>,
    pub selection: CoffTextComdatSelection,
    pub section_number: u16,
    pub associated_section: Option<u16>,
}

impl CoffSectionSet {
    const fn empty() -> Self {
        Self {
            words: [0; COFF_SECTION_SET_WORDS],
        }
    }

    fn contains(&self, section: usize) -> bool {
        section <= MAX_COFF_SECTIONS && self.words[section / 64] & (1u64 << (section % 64)) != 0
    }

    fn insert(&mut self, section: usize) -> Result<(), LinkerError> {
        if section > MAX_COFF_SECTIONS {
            return Err(LinkerError::TooManyCoffSections);
        }
        self.words[section / 64] |= 1u64 << (section % 64);
        Ok(())
    }

    fn remove(&mut self, section: usize) -> Result<(), LinkerError> {
        if section > MAX_COFF_SECTIONS {
            return Err(LinkerError::TooManyCoffSections);
        }
        self.words[section / 64] &= !(1u64 << (section % 64));
        Ok(())
    }
}

impl<'a> CoffComdatSections<'a> {
    fn validate_object(&self, object: &[u8]) -> Result<(), LinkerError> {
        if self.object.as_ptr() == object.as_ptr() && self.object.len() == object.len() {
            Ok(())
        } else {
            Err(LinkerError::InvalidCoffAssociation)
        }
    }

    pub fn sections(&self) -> CoffComdatSectionIter<'_, 'a> {
        CoffComdatSectionIter {
            inventory: self,
            next_section: 1,
            remaining: self.len,
        }
    }

    pub fn section(&self, section_number: u16) -> Option<CoffComdatSection> {
        coff_comdat_metadata_for_section(self.object, self.section_count, section_number)
            .ok()
            .flatten()
    }

    pub fn root_section(&self, section_number: u16) -> Option<u16> {
        let mut section = self.section(section_number)?;
        for _ in 0..self.len {
            if section.selection != CoffTextComdatSelection::Associative {
                return Some(section.section_number);
            }
            section = self.section(section.associated_section?)?;
        }
        None
    }
}

impl Iterator for CoffComdatSectionIter<'_, '_> {
    type Item = CoffComdatSection;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_section <= self.inventory.section_count {
            let section = self.next_section;
            self.next_section += 1;
            if let Some(metadata) = self.inventory.section(section) {
                self.remaining -= 1;
                return Some(metadata);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for CoffComdatSectionIter<'_, '_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeWritableData<'a, 'relocations> {
    pub symbol: &'a str,
    pub selection: PeWritableComdatSelection,
    pub initialized: &'a [u8],
    pub zeroed_size: usize,
    pub relocations: &'relocations [PeWritableRelocation<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeReadonlyAbsoluteRelocation<'a> {
    pub readonly_owner: &'a str,
    pub readonly_identity: Option<CoffSectionIdentity>,
    pub readonly_offset: usize,
    pub target_symbol: &'a str,
    pub target_identity: Option<CoffSectionIdentity>,
    pub target_offset: usize,
    pub addend: i64,
    pub kind: PeReadonlyRelocationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeReadonlyRelocationKind {
    /// `IMAGE_REL_AMD64_ADDR64`: fixed-image virtual address plus addend.
    Address64,
    /// `IMAGE_REL_AMD64_ADDR32NB`: image-relative RVA plus addend.
    Address32NoBase,
    /// `IMAGE_REL_AMD64_REL32` through `REL32_5`. The encoded value is
    /// relative to the end of the four-byte field plus this many trailing
    /// instruction bytes.
    Relative32 { trailing_bytes: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeReadonlyAbsoluteRelocations<'a> {
    relocations: [PeReadonlyAbsoluteRelocation<'a>; MAX_PE_READONLY_RELOCATIONS],
    length: usize,
}

impl<'a> PeReadonlyAbsoluteRelocations<'a> {
    pub fn relocations(&self) -> &[PeReadonlyAbsoluteRelocation<'a>] {
        &self.relocations[..self.length]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInputSelection {
    indices: [usize; MAX_LINK_FRAGMENTS],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSectionSelection {
    indices: [u16; MAX_LINK_INPUTS],
    length: usize,
    object_address: usize,
    object_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfLinkSectionSelections {
    selections: [ElfSectionSelection; MAX_LINK_INPUTS],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfObjectSymbolDefinition<'a> {
    pub symbol: &'a str,
    pub binding: ElfSelectedSymbolBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfObjectSymbolInventory<'a> {
    definitions: [ElfObjectSymbolDefinition<'a>; MAX_ARCHIVE_SYMBOLS],
    definition_count: usize,
    references: [&'a str; MAX_ARCHIVE_SYMBOLS],
    reference_count: usize,
}

pub struct CoffObjectSymbolInventory<'a> {
    object: &'a [u8],
    symbol_offset: usize,
    symbol_count: usize,
    symbols_end: usize,
    string_size: usize,
    import_name: Option<&'a str>,
}

impl<'a> CoffObjectSymbolInventory<'a> {
    pub fn symbols(&self) -> CoffObjectSymbols<'a> {
        CoffObjectSymbols {
            object: self.object,
            symbol_offset: self.symbol_offset,
            symbol_count: self.symbol_count,
            symbols_end: self.symbols_end,
            string_size: self.string_size,
            import_name: self.import_name,
            index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoffObjectSymbolKind {
    Definition,
    Reference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffObjectSymbol<'a> {
    pub name: &'a str,
    pub kind: CoffObjectSymbolKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffShortImport<'a> {
    pub symbol: &'a str,
    pub library: &'a str,
}

pub struct CoffObjectSymbols<'a> {
    object: &'a [u8],
    symbol_offset: usize,
    symbol_count: usize,
    symbols_end: usize,
    string_size: usize,
    import_name: Option<&'a str>,
    index: usize,
}

fn decode_x86_64_coff_short_import_header(
    object: &[u8],
) -> Result<Option<CoffShortImport<'_>>, LinkerError> {
    if object.get(..4) != Some(b"\0\0\xff\xff") {
        return Ok(None);
    }
    if read_u16(object, 4)? != 0
        || read_u16(object, 6)? != 0x8664
        || read_u16(object, 16)? != 0
        || read_u16(object, 18)? != 4
    {
        return Err(LinkerError::UnsupportedCoff);
    }
    let payload_size = usize::try_from(read_u32(object, 12)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let payload_end = 20usize
        .checked_add(payload_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    if payload_end != object.len() {
        return Err(LinkerError::InvalidCoff);
    }
    let payload = object.get(20..payload_end).ok_or(LinkerError::InvalidCoff)?;
    let name_end = payload
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(LinkerError::InvalidCoff)?;
    let library_start = name_end
        .checked_add(1)
        .ok_or(LinkerError::OffsetOverflow)?;
    let library_end = payload[library_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| library_start + offset)
        .ok_or(LinkerError::InvalidCoff)?;
    if name_end == 0 || library_end == library_start || library_end + 1 != payload.len() {
        return Err(LinkerError::InvalidCoff);
    }
    let symbol = core::str::from_utf8(&payload[..name_end])
        .map_err(|_| LinkerError::InvalidCoff)?;
    validate_symbol(symbol)?;
    let library = core::str::from_utf8(&payload[library_start..library_end])
        .map_err(|_| LinkerError::InvalidCoff)?;
    validate_pe_import_library(library)?;
    Ok(Some(CoffShortImport { symbol, library }))
}

fn validate_pe_import_library(library: &str) -> Result<(), LinkerError> {
    if library.is_empty()
        || !library.ends_with(".dll")
        || !library
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LinkerError::UnsupportedCoff);
    }
    Ok(())
}

pub fn x86_64_coff_short_import(
    object: &[u8],
) -> Result<Option<CoffShortImport<'_>>, LinkerError> {
    decode_x86_64_coff_short_import_header(object)
}

pub fn decode_x86_64_coff_short_import<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<Option<LinkInput<'data, 'relocations, 'definitions>>, LinkerError> {
    let Some(import) = decode_x86_64_coff_short_import_header(object)? else {
        return Ok(None);
    };
    const THUNK: &[u8] = &[0xff, 0x25, 0, 0, 0, 0];
    relocation_storage[0] = LinkRelocation {
        offset: 2,
        target: LinkRelocationTarget::PeImportAddress {
            library: import.library,
            symbol: import.symbol,
        },
        addend: -4,
    };
    Ok(Some(LinkInput {
        symbol: import.symbol,
        symbol_target: LinkDefinitionTarget::Text(0),
        additional_definitions: &[],
        text: THUNK,
        readonly_data: &[],
        relocations: &relocation_storage[..1],
    }))
}

impl<'a> Iterator for CoffObjectSymbols<'a> {
    type Item = Result<CoffObjectSymbol<'a>, LinkerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(name) = self.import_name {
            if self.index == 0 {
                self.index = 1;
                return Some(Ok(CoffObjectSymbol {
                    name,
                    kind: CoffObjectSymbolKind::Definition,
                }));
            }
            return None;
        }
        while self.index < self.symbol_count {
            let offset = self.symbol_offset + self.index * 18;
            let auxiliary = match self.object.get(offset + 17) {
                Some(auxiliary) => usize::from(*auxiliary),
                None => return Some(Err(LinkerError::InvalidCoff)),
            };
            self.index += auxiliary + 1;
            if self.object.get(offset + 16) != Some(&2) {
                continue;
            }
            let section = match read_i16(self.object, offset + 12) {
                Ok(section) => section,
                Err(error) => return Some(Err(error)),
            };
            let kind = if section > 0 {
                CoffObjectSymbolKind::Definition
            } else if section == 0 {
                CoffObjectSymbolKind::Reference
            } else {
                continue;
            };
            let name =
                match coff_symbol_name(self.object, offset, self.symbols_end, self.string_size) {
                    Ok(name) => name,
                    Err(error) => return Some(Err(error)),
                };
            return Some(Ok(CoffObjectSymbol { name, kind }));
        }
        None
    }
}

impl<'a> ElfObjectSymbolInventory<'a> {
    pub fn definitions(&self) -> &[ElfObjectSymbolDefinition<'a>] {
        &self.definitions[..self.definition_count]
    }

    pub fn references(&self) -> &[&'a str] {
        &self.references[..self.reference_count]
    }
}

impl ElfLinkSectionSelections {
    pub fn selections(&self) -> &[ElfSectionSelection] {
        &self.selections[..self.length]
    }
}

/// Inventories externally visible COFF definitions and undefined externals
/// directly from the bounded symbol table. Archive fixed-point extraction uses
/// this metadata pass instead of repeatedly decoding every content fragment.
pub fn inventory_x86_64_coff_symbols(
    object: &[u8],
) -> Result<CoffObjectSymbolInventory<'_>, LinkerError> {
    if let Some(import) = decode_x86_64_coff_short_import_header(object)? {
        return Ok(CoffObjectSymbolInventory {
            object,
            symbol_offset: 0,
            symbol_count: 0,
            symbols_end: 0,
            string_size: 0,
            import_name: Some(import.symbol),
        });
    }
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    let mut index = 0usize;
    while index < symbol_count {
        let symbol = symbol_offset
            .checked_add(index.checked_mul(18).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        if index
            .checked_add(auxiliary)
            .filter(|end| *end < symbol_count)
            .is_none()
        {
            return Err(LinkerError::InvalidCoff);
        }
        if *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? == 2 {
            let section = read_i16(object, symbol + 12)?;
            if section > 0 {
                if usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?
                    > section_count
                {
                    return Err(LinkerError::InvalidCoff);
                }
                let name = coff_symbol_name(object, symbol, symbols_end, string_size)?;
                validate_symbol(name)?;
            } else if section == 0 {
                if read_u32(object, symbol + 8)? != 0 {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let name = coff_symbol_name(object, symbol, symbols_end, string_size)?;
                validate_symbol(name)?;
            }
        }
        index = index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(CoffObjectSymbolInventory {
        object,
        symbol_offset,
        symbol_count,
        symbols_end,
        string_size,
        import_name: None,
    })
}

/// Inventories externally visible definitions and relocation-referenced
/// undefined symbols without admitting or decoding unrelated content sections.
pub fn inventory_x86_64_elf_symbols(
    object: &[u8],
) -> Result<ElfObjectSymbolInventory<'_>, LinkerError> {
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || read_u16_elf(object, 16)? != 1
        || read_u16_elf(object, 18)? != 62
        || read_u16_elf(object, 58)? != 64
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) {
        return Err(LinkerError::UnsupportedElf);
    }
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? == 2 && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    let strings_index = usize::try_from(read_u32_elf(object, symbols_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    if strings_index >= section_count || read_u64_elf(object, symbols_header + 56)? != 24 {
        return Err(LinkerError::InvalidElf);
    }
    let strings_header = elf_section_header(section_offset, section_count, strings_index)?;
    if read_u32_elf(object, strings_header + 4)? != 3 {
        return Err(LinkerError::InvalidElf);
    }
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    let empty = ElfObjectSymbolDefinition {
        symbol: "",
        binding: ElfSelectedSymbolBinding::Global,
    };
    let mut inventory = ElfObjectSymbolInventory {
        definitions: [empty; MAX_ARCHIVE_SYMBOLS],
        definition_count: 0,
        references: [""; MAX_ARCHIVE_SYMBOLS],
        reference_count: 0,
    };
    for record in symbols[24..].chunks_exact(24) {
        let binding = match *record.get(4).ok_or(LinkerError::InvalidElf)? >> 4 {
            1 => ElfSelectedSymbolBinding::Global,
            2 => ElfSelectedSymbolBinding::Weak,
            _ => continue,
        };
        let section = usize::from(read_u16_elf(record, 6)?);
        if section == 0 || section == 0xfff1 {
            continue;
        }
        if section != 0xfff2 && section >= section_count {
            return Err(LinkerError::InvalidElf);
        }
        if section == 0xfff2 {
            validate_elf_common_shape(
                to_usize_elf(read_u64_elf(record, 16)?)?,
                to_usize_elf(read_u64_elf(record, 8)?)?,
            )?;
        }
        let name_offset =
            usize::try_from(read_u32_elf(record, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        if name_offset == 0 {
            return Err(LinkerError::EmptySymbol);
        }
        let symbol = elf_string(strings, name_offset)?;
        validate_symbol(symbol)?;
        if inventory.definitions[..inventory.definition_count]
            .iter()
            .any(|definition| definition.symbol == symbol)
        {
            return Err(LinkerError::DuplicateSymbol);
        }
        if inventory.definition_count == inventory.definitions.len() {
            return Err(LinkerError::TooManyArchiveSymbols);
        }
        inventory.definitions[inventory.definition_count] =
            ElfObjectSymbolDefinition { symbol, binding };
        inventory.definition_count += 1;
    }
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? != 4 {
            continue;
        }
        if usize::try_from(read_u32_elf(object, header + 40)?)
            .map_err(|_| LinkerError::OffsetOverflow)?
            != symbols_index
            || read_u64_elf(object, header + 56)? != 24
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        if records.len() % 24 != 0 {
            return Err(LinkerError::InvalidElf);
        }
        for relocation in records.chunks_exact(24) {
            let symbol_index = to_usize_elf(read_u64_elf(relocation, 8)? >> 32)?;
            let symbol_offset = symbol_index
                .checked_mul(24)
                .ok_or(LinkerError::OffsetOverflow)?;
            symbols
                .get(symbol_offset..symbol_offset + 24)
                .ok_or(LinkerError::InvalidElf)?;
            if read_u16_elf(symbols, symbol_offset + 6)? != 0 {
                continue;
            }
            let binding = *symbols
                .get(symbol_offset + 4)
                .ok_or(LinkerError::InvalidElf)?
                >> 4;
            if !matches!(binding, 1 | 2) {
                continue;
            }
            let name_offset = usize::try_from(read_u32_elf(symbols, symbol_offset)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if name_offset == 0 {
                return Err(LinkerError::EmptySymbol);
            }
            let symbol = elf_string(strings, name_offset)?;
            if inventory.references[..inventory.reference_count].contains(&symbol) {
                continue;
            }
            if inventory.reference_count == inventory.references.len() {
                return Err(LinkerError::TooManyArchiveSymbols);
            }
            inventory.references[inventory.reference_count] = symbol;
            inventory.reference_count += 1;
        }
    }
    Ok(inventory)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSectionKind {
    Text,
    ReadonlyData,
    PreInitializerArray,
    InitializerArray,
    FinalizerArray,
    WritableData,
    InitializedTls,
    ZeroedTls,
    ZeroedData,
    Unwind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedSection<'a> {
    pub index: u16,
    pub name: &'a str,
    pub kind: ElfSectionKind,
    pub bytes: &'a [u8],
    pub size: usize,
    pub alignment: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedSections<'a> {
    sections: [ElfSelectedSection<'a>; MAX_LINK_INPUTS],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSelectedRelocationKind {
    Absolute64,
    Absolute32,
    SignedAbsolute32,
    PcRelative32,
    PltRelative32,
    GotPcRelative32,
    ThreadPointerOffset32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSelectedRelocationTarget<'a> {
    Section { index: u16, offset: usize },
    Symbol(&'a str),
    Absolute(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedRelocation<'a> {
    pub section_index: u16,
    pub offset: usize,
    pub kind: ElfSelectedRelocationKind,
    pub target: ElfSelectedRelocationTarget<'a>,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedRelocations<'a> {
    relocations: [ElfSelectedRelocation<'a>; MAX_LINK_RELOCATIONS],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSelectedSymbolBinding {
    Global,
    Weak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSelectedSymbolVisibility {
    Default,
    Hidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfSelectedSymbolKind {
    Unspecified,
    Object,
    Function,
    ThreadLocal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedDefinition<'a> {
    pub name: &'a str,
    pub section_index: u16,
    pub offset: usize,
    pub size: usize,
    pub binding: ElfSelectedSymbolBinding,
    pub visibility: ElfSelectedSymbolVisibility,
    pub kind: ElfSelectedSymbolKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedDefinitions<'a> {
    definitions: [ElfSelectedDefinition<'a>; MAX_LINK_DEFINITIONS],
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedObject<'data, 'view> {
    pub sections: &'view ElfSelectedSections<'data>,
    pub definitions: &'view ElfSelectedDefinitions<'data>,
    pub relocations: &'view ElfSelectedRelocations<'data>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedSectionLayout {
    pub input_index: u16,
    pub section_index: u16,
    pub offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedCommonLayout {
    pub input_index: u16,
    pub definition_index: u16,
    pub offset: usize,
    pub size: usize,
    pub alignment: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedLayout {
    sections: [ElfSelectedSectionLayout; MAX_LINK_INPUTS],
    length: usize,
    commons: [ElfSelectedCommonLayout; MAX_LINK_DEFINITIONS],
    common_length: usize,
    pub text_length: usize,
    pub readonly_offset: usize,
    pub readonly_length: usize,
    pub writable_offset: usize,
    pub preinitializer_start: usize,
    pub preinitializer_end: usize,
    pub initializer_start: usize,
    pub initializer_end: usize,
    pub finalizer_start: usize,
    pub finalizer_end: usize,
    pub tls_offset: usize,
    pub tls_file_length: usize,
    pub tls_memory_length: usize,
    pub tls_alignment: usize,
    pub file_length: usize,
    pub memory_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSelectedLinkedImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    pub length: usize,
    pub memory_length: usize,
    pub entry_offset: usize,
    pub layout: ElfSelectedLayout,
}

impl<const MAX_BYTES: usize> ElfSelectedLinkedImage<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl ElfSelectedLayout {
    pub fn sections(&self) -> &[ElfSelectedSectionLayout] {
        &self.sections[..self.length]
    }

    pub fn commons(&self) -> &[ElfSelectedCommonLayout] {
        &self.commons[..self.common_length]
    }
}

impl<'a> ElfSelectedDefinitions<'a> {
    pub fn definitions(&self) -> &[ElfSelectedDefinition<'a>] {
        &self.definitions[..self.length]
    }
}

/// Computes a deterministic permission-grouped layout for selected sections.
/// Offsets are relative to the future executable payload; serialization adds
/// its fixed image base and header reservation separately.
pub fn layout_x86_64_elf_selected_sections(
    inputs: &[ElfSelectedObject<'_, '_>],
) -> Result<ElfSelectedLayout, LinkerError> {
    const PAGE: usize = 0x1000;
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs);
    }
    let mut definition_count = 0usize;
    let mut relocation_count = 0usize;
    for input in inputs {
        definition_count = definition_count
            .checked_add(input.definitions.definitions().len())
            .ok_or(LinkerError::OffsetOverflow)?;
        relocation_count = relocation_count
            .checked_add(input.relocations.relocations().len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if definition_count > MAX_LINK_DEFINITIONS {
        return Err(LinkerError::TooManyDefinitions);
    }
    if relocation_count > MAX_LINK_RELOCATIONS {
        return Err(LinkerError::TooManyRelocations);
    }
    let has_readonly = inputs.iter().any(|input| {
        input.sections.sections().iter().any(|section| {
            matches!(
                section.kind,
                ElfSectionKind::ReadonlyData | ElfSectionKind::Unwind
            )
        })
    });
    let has_tls = inputs.iter().any(|input| {
        input.sections.sections().iter().any(|section| {
            matches!(
                section.kind,
                ElfSectionKind::InitializedTls | ElfSectionKind::ZeroedTls
            )
        })
    });
    let has_writable = inputs.iter().any(|input| {
        input
            .definitions
            .definitions()
            .iter()
            .any(|definition| definition.section_index == 0xfff2)
            || input.sections.sections().iter().any(|section| {
                matches!(
                    section.kind,
                    ElfSectionKind::PreInitializerArray
                        | ElfSectionKind::InitializerArray
                        | ElfSectionKind::FinalizerArray
                        | ElfSectionKind::WritableData
                        | ElfSectionKind::InitializedTls
                        | ElfSectionKind::ZeroedTls
                        | ElfSectionKind::ZeroedData
                )
            })
    });
    let empty = ElfSelectedSectionLayout {
        input_index: 0,
        section_index: 0,
        offset: 0,
    };
    let empty_common = ElfSelectedCommonLayout {
        input_index: 0,
        definition_index: 0,
        offset: 0,
        size: 0,
        alignment: 1,
    };
    let mut layout = ElfSelectedLayout {
        sections: [empty; MAX_LINK_INPUTS],
        length: 0,
        commons: [empty_common; MAX_LINK_DEFINITIONS],
        common_length: 0,
        text_length: 0,
        readonly_offset: 0,
        readonly_length: 0,
        writable_offset: 0,
        preinitializer_start: 0,
        preinitializer_end: 0,
        initializer_start: 0,
        initializer_end: 0,
        finalizer_start: 0,
        finalizer_end: 0,
        tls_offset: 0,
        tls_file_length: 0,
        tls_memory_length: 0,
        tls_alignment: 1,
        file_length: 0,
        memory_length: 0,
    };
    let groups = [
        ElfSectionKind::Text,
        ElfSectionKind::ReadonlyData,
        ElfSectionKind::Unwind,
        ElfSectionKind::PreInitializerArray,
        ElfSectionKind::InitializerArray,
        ElfSectionKind::FinalizerArray,
        ElfSectionKind::WritableData,
        ElfSectionKind::InitializedTls,
        ElfSectionKind::ZeroedTls,
        ElfSectionKind::ZeroedData,
    ];
    let mut cursor = 0usize;
    for kind in groups {
        if kind == ElfSectionKind::ReadonlyData {
            layout.text_length = cursor;
            if has_readonly {
                cursor = align(cursor, PAGE)?;
            }
            layout.readonly_offset = cursor;
        } else if kind == ElfSectionKind::PreInitializerArray {
            layout.readonly_length = cursor
                .checked_sub(layout.readonly_offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            if has_writable {
                cursor = align(cursor, PAGE)?;
            }
            layout.writable_offset = cursor;
        } else if kind == ElfSectionKind::InitializedTls && has_tls {
            for input in inputs {
                for section in input.sections.sections() {
                    if matches!(
                        section.kind,
                        ElfSectionKind::InitializedTls | ElfSectionKind::ZeroedTls
                    ) {
                        layout.tls_alignment = layout.tls_alignment.max(section.alignment);
                    }
                }
            }
            cursor = align(cursor, layout.tls_alignment)?;
            layout.tls_offset = cursor;
        } else if kind == ElfSectionKind::ZeroedTls && has_tls {
            layout.file_length = cursor;
            layout.tls_file_length = cursor
                .checked_sub(layout.tls_offset)
                .ok_or(LinkerError::OffsetOverflow)?;
        } else if kind == ElfSectionKind::ZeroedData && layout.file_length == 0 {
            layout.file_length = cursor;
        }
        if matches!(
            kind,
            ElfSectionKind::PreInitializerArray
                | ElfSectionKind::InitializerArray
                | ElfSectionKind::FinalizerArray
        ) {
            append_ordered_elf_array_sections(inputs, kind, &mut layout, &mut cursor)?;
        } else {
            append_elf_sections_in_input_order(inputs, kind, &mut layout, &mut cursor)?;
        }
        match kind {
            ElfSectionKind::PreInitializerArray => {
                layout.preinitializer_start = layout.writable_offset;
                layout.preinitializer_end = cursor;
            }
            ElfSectionKind::InitializerArray => {
                layout.initializer_start = layout.preinitializer_end;
                layout.initializer_end = cursor;
            }
            ElfSectionKind::FinalizerArray => {
                layout.finalizer_start = layout.initializer_end;
                layout.finalizer_end = cursor;
            }
            ElfSectionKind::InitializedTls | ElfSectionKind::ZeroedTls if has_tls => {
                layout.tls_memory_length = cursor
                    .checked_sub(layout.tls_offset)
                    .ok_or(LinkerError::OffsetOverflow)?;
            }
            _ => {}
        }
    }
    if layout.file_length == 0 {
        layout.file_length = cursor;
    }
    append_elf_common_layouts(inputs, &mut layout, &mut cursor)?;
    layout.memory_length = cursor;
    Ok(layout)
}

fn append_elf_common_layouts(
    inputs: &[ElfSelectedObject<'_, '_>],
    layout: &mut ElfSelectedLayout,
    cursor: &mut usize,
) -> Result<(), LinkerError> {
    for (input_index, input) in inputs.iter().enumerate() {
        for (definition_index, definition) in input.definitions.definitions().iter().enumerate() {
            if definition.section_index != 0xfff2
                || resolve_selected_definition(inputs, definition.name)?
                    != Some((input_index, definition))
            {
                continue;
            }
            let mut size = definition.size;
            let mut alignment = definition.offset;
            for candidate_input in inputs {
                for candidate in candidate_input.definitions.definitions() {
                    if candidate.section_index == 0xfff2 && candidate.name == definition.name {
                        size = size.max(candidate.size);
                        alignment = alignment.max(candidate.offset);
                    }
                }
            }
            validate_elf_common_shape(size, alignment)?;
            if layout.common_length == layout.commons.len() {
                return Err(LinkerError::TooManyDefinitions);
            }
            *cursor = align(*cursor, alignment)?;
            layout.commons[layout.common_length] = ElfSelectedCommonLayout {
                input_index: u16::try_from(input_index).map_err(|_| LinkerError::TooManyInputs)?,
                definition_index: u16::try_from(definition_index)
                    .map_err(|_| LinkerError::TooManyDefinitions)?,
                offset: *cursor,
                size,
                alignment,
            };
            layout.common_length += 1;
            *cursor = cursor
                .checked_add(size)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(())
}

fn append_elf_sections_in_input_order(
    inputs: &[ElfSelectedObject<'_, '_>],
    kind: ElfSectionKind,
    layout: &mut ElfSelectedLayout,
    cursor: &mut usize,
) -> Result<(), LinkerError> {
    for (input_index, input) in inputs.iter().enumerate() {
        for section in input.sections.sections() {
            if section.kind == kind {
                append_elf_section_layout(layout, cursor, input_index, section)?;
            }
        }
    }
    Ok(())
}

fn append_ordered_elf_array_sections(
    inputs: &[ElfSelectedObject<'_, '_>],
    kind: ElfSectionKind,
    layout: &mut ElfSelectedLayout,
    cursor: &mut usize,
) -> Result<(), LinkerError> {
    let mut ordered = [(0u16, 0u8, 0u16, 0u16); MAX_LINK_INPUTS];
    let mut length = 0usize;
    for (input_index, input) in inputs.iter().enumerate() {
        for section in input.sections.sections() {
            if section.kind != kind {
                continue;
            }
            if length == ordered.len() {
                return Err(LinkerError::TooManyElfSections);
            }
            let (priority, base_rank) = elf_array_section_priority(section.name, kind)?;
            ordered[length] = (
                priority,
                base_rank,
                u16::try_from(input_index).map_err(|_| LinkerError::TooManyInputs)?,
                section.index,
            );
            let mut position = length;
            while position != 0
                && elf_array_section_follows(
                    (ordered[position - 1].0, ordered[position - 1].1),
                    (priority, base_rank),
                )
            {
                ordered.swap(position - 1, position);
                position -= 1;
            }
            length += 1;
        }
    }
    for &(_, _, input_index, section_index) in &ordered[..length] {
        let input_index = usize::from(input_index);
        let section = inputs[input_index]
            .sections
            .sections()
            .iter()
            .find(|section| section.index == section_index)
            .ok_or(LinkerError::InvalidElf)?;
        append_elf_section_layout(layout, cursor, input_index, section)?;
    }
    Ok(())
}

fn elf_array_section_follows(left: (u16, u8), right: (u16, u8)) -> bool {
    if left.1 != right.1 {
        return left.1 > right.1;
    }
    if left.1 != 0 {
        return false;
    }
    left.0 > right.0
}

fn append_elf_section_layout(
    layout: &mut ElfSelectedLayout,
    cursor: &mut usize,
    input_index: usize,
    section: &ElfSelectedSection<'_>,
) -> Result<(), LinkerError> {
    if layout.length == layout.sections.len() {
        return Err(LinkerError::TooManyElfSections);
    }
    *cursor = align(*cursor, section.alignment)?;
    layout.sections[layout.length] = ElfSelectedSectionLayout {
        input_index: u16::try_from(input_index).map_err(|_| LinkerError::TooManyInputs)?,
        section_index: section.index,
        offset: *cursor,
    };
    layout.length += 1;
    *cursor = cursor
        .checked_add(section.size)
        .ok_or(LinkerError::OffsetOverflow)?;
    Ok(())
}

fn elf_array_section_priority(name: &str, kind: ElfSectionKind) -> Result<(u16, u8), LinkerError> {
    let base = match kind {
        ElfSectionKind::PreInitializerArray => ".preinit_array",
        ElfSectionKind::InitializerArray => ".init_array",
        ElfSectionKind::FinalizerArray => ".fini_array",
        _ => return Err(LinkerError::UnsupportedElf),
    };
    if name == base {
        return Ok((u16::MAX, 1));
    }
    if kind == ElfSectionKind::PreInitializerArray {
        return Err(LinkerError::UnsupportedElf);
    }
    let suffix = name
        .strip_prefix(base)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .ok_or(LinkerError::UnsupportedElf)?;
    if suffix.is_empty() || suffix.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(LinkerError::UnsupportedElf);
    }
    let mut priority = 0u16;
    for digit in suffix.bytes() {
        priority = priority
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(digit - b'0')))
            .ok_or(LinkerError::UnsupportedElf)?;
    }
    Ok((priority, 0))
}

/// Copies selected content into its frozen layout and applies static x86-64
/// relocations after resolving global/weak definitions across objects.
pub fn link_x86_64_elf_selected_sections<const MAX_BYTES: usize>(
    inputs: &[ElfSelectedObject<'_, '_>],
    entry_symbol: &str,
    virtual_base: u64,
) -> Result<ElfSelectedLinkedImage<MAX_BYTES>, LinkerError> {
    validate_symbol(entry_symbol)?;
    let layout = layout_x86_64_elf_selected_sections(inputs)?;
    if layout.file_length > MAX_BYTES || layout.memory_length > MAX_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    validate_selected_definition_set(inputs)?;
    let (entry_input, entry_definition) =
        resolve_selected_definition(inputs, entry_symbol)?.ok_or(LinkerError::UndefinedSymbol)?;
    let entry_section = inputs[entry_input]
        .sections
        .sections()
        .iter()
        .find(|section| section.index == entry_definition.section_index)
        .ok_or(LinkerError::InvalidElf)?;
    if entry_section.kind != ElfSectionKind::Text
        || entry_definition.kind == ElfSelectedSymbolKind::Object
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let entry_offset =
        selected_section_layout_offset(&layout, entry_input, entry_definition.section_index)?
            .checked_add(entry_definition.offset)
            .ok_or(LinkerError::OffsetOverflow)?;
    let mut bytes = [0u8; MAX_BYTES];
    for section_layout in layout.sections() {
        let input_index = usize::from(section_layout.input_index);
        let section = inputs[input_index]
            .sections
            .sections()
            .iter()
            .find(|section| section.index == section_layout.section_index)
            .ok_or(LinkerError::InvalidElf)?;
        if !section.bytes.is_empty() {
            copy_at(&mut bytes, section_layout.offset, section.bytes)?;
        }
    }
    for (input_index, input) in inputs.iter().enumerate() {
        for relocation in input.relocations.relocations() {
            let section_base =
                selected_section_layout_offset(&layout, input_index, relocation.section_index)?;
            let place = section_base
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let (target, target_is_absolute, target_is_tls) = match relocation.target {
                ElfSelectedRelocationTarget::Section { index, offset } => {
                    let section = input
                        .sections
                        .sections()
                        .iter()
                        .find(|section| section.index == index)
                        .ok_or(LinkerError::InvalidElf)?;
                    (
                        selected_section_layout_offset(&layout, input_index, index)?
                            .checked_add(offset)
                            .ok_or(LinkerError::OffsetOverflow)?,
                        false,
                        matches!(
                            section.kind,
                            ElfSectionKind::InitializedTls | ElfSectionKind::ZeroedTls
                        ),
                    )
                }
                ElfSelectedRelocationTarget::Symbol(symbol) => {
                    if let Some((target_input, definition)) =
                        resolve_selected_definition(inputs, symbol)?
                    {
                        if definition.section_index == 0xfff2 {
                            (
                                selected_common_layout_offset(&layout, inputs, symbol)?,
                                false,
                                false,
                            )
                        } else {
                            (
                                selected_section_layout_offset(
                                    &layout,
                                    target_input,
                                    definition.section_index,
                                )?
                                .checked_add(definition.offset)
                                .ok_or(LinkerError::OffsetOverflow)?,
                                false,
                                definition.kind == ElfSelectedSymbolKind::ThreadLocal,
                            )
                        }
                    } else {
                        (
                            selected_elf_array_boundary(&layout, symbol)
                                .ok_or(LinkerError::UndefinedSymbol)?,
                            false,
                            false,
                        )
                    }
                }
                ElfSelectedRelocationTarget::Absolute(value) => (
                    usize::try_from(value).map_err(|_| LinkerError::OffsetOverflow)?,
                    true,
                    false,
                ),
            };
            match relocation.kind {
                ElfSelectedRelocationKind::Absolute64 => {
                    let address = if target_is_absolute {
                        u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    } else {
                        virtual_base
                            .checked_add(
                                u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?,
                            )
                            .ok_or(LinkerError::OffsetOverflow)?
                    };
                    let value = i128::from(address)
                        .checked_add(i128::from(relocation.addend))
                        .and_then(|value| u64::try_from(value).ok())
                        .ok_or(LinkerError::RelocationOverflow)?;
                    patch_u64(&mut bytes, place, value)?;
                }
                ElfSelectedRelocationKind::Absolute32 => {
                    let address = if target_is_absolute {
                        u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    } else {
                        virtual_base
                            .checked_add(
                                u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?,
                            )
                            .ok_or(LinkerError::OffsetOverflow)?
                    };
                    let value = i128::from(address)
                        .checked_add(i128::from(relocation.addend))
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or(LinkerError::RelocationOverflow)?;
                    patch_u32(&mut bytes, place, value)?;
                }
                ElfSelectedRelocationKind::SignedAbsolute32 => {
                    let address = if target_is_absolute {
                        i128::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    } else {
                        i128::from(virtual_base)
                            + i128::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    };
                    let value = address
                        .checked_add(i128::from(relocation.addend))
                        .and_then(|value| i32::try_from(value).ok())
                        .ok_or(LinkerError::RelocationOverflow)?;
                    patch_i32(&mut bytes, place, value)?;
                }
                ElfSelectedRelocationKind::PcRelative32
                | ElfSelectedRelocationKind::PltRelative32
                | ElfSelectedRelocationKind::GotPcRelative32 => {
                    let target_address = if target_is_absolute {
                        i128::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    } else {
                        i128::from(virtual_base)
                            + i128::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?
                    };
                    let place_address = i128::from(virtual_base)
                        + i128::try_from(place).map_err(|_| LinkerError::OffsetOverflow)?;
                    let displacement = target_address
                        .checked_add(i128::from(relocation.addend))
                        .and_then(|value| value.checked_sub(place_address))
                        .and_then(|value| i32::try_from(value).ok())
                        .ok_or(LinkerError::RelocationOverflow)?;
                    if relocation.kind == ElfSelectedRelocationKind::GotPcRelative32 {
                        relax_selected_gotpcrel(&mut bytes, place)?;
                    }
                    patch_i32(&mut bytes, place, displacement)?;
                }
                ElfSelectedRelocationKind::ThreadPointerOffset32 => {
                    if !target_is_tls || target_is_absolute || layout.tls_memory_length == 0 {
                        return Err(LinkerError::UnsupportedElf);
                    }
                    let tls_end = layout
                        .tls_offset
                        .checked_add(layout.tls_memory_length)
                        .ok_or(LinkerError::OffsetOverflow)?;
                    let value = i128::try_from(target)
                        .map_err(|_| LinkerError::OffsetOverflow)?
                        .checked_add(i128::from(relocation.addend))
                        .and_then(|value| value.checked_sub(i128::try_from(tls_end).ok()?))
                        .and_then(|value| i32::try_from(value).ok())
                        .ok_or(LinkerError::RelocationOverflow)?;
                    patch_i32(&mut bytes, place, value)?;
                }
            }
        }
    }
    Ok(ElfSelectedLinkedImage {
        bytes,
        length: layout.file_length,
        memory_length: layout.memory_length,
        entry_offset,
        layout,
    })
}

/// Serializes the selected-section link result as a fixed-address, import-free
/// ELF64 executable with page-separated load permissions.
pub fn link_x86_64_elf_selected_executable<
    const MAX_IMAGE_BYTES: usize,
    const MAX_PAYLOAD_BYTES: usize,
>(
    inputs: &[ElfSelectedObject<'_, '_>],
    entry_symbol: &str,
) -> Result<ElfImage<MAX_IMAGE_BYTES>, LinkerError> {
    const IMAGE_BASE: u64 = 0x40_0000;
    const PAYLOAD_OFFSET: usize = 0x1000;
    let linked = link_x86_64_elf_selected_sections::<MAX_PAYLOAD_BYTES>(
        inputs,
        entry_symbol,
        IMAGE_BASE + PAYLOAD_OFFSET as u64,
    )?;
    let has_text = linked.layout.text_length != 0;
    let has_readonly = linked.layout.readonly_length != 0;
    let has_writable = linked.memory_length > linked.layout.writable_offset;
    let has_tls = linked.layout.tls_memory_length != 0;
    if !has_text {
        return Err(LinkerError::UnsupportedElf);
    }
    let program_count = 1
        + usize::from(has_text)
        + usize::from(has_readonly)
        + usize::from(has_writable)
        + usize::from(has_tls);
    let header_bytes = 64usize
        .checked_add(program_count * 56)
        .ok_or(LinkerError::OffsetOverflow)?;
    if header_bytes > PAYLOAD_OFFSET {
        return Err(LinkerError::OutputTooSmall);
    }
    let length = PAYLOAD_OFFSET
        .checked_add(linked.length)
        .ok_or(LinkerError::OffsetOverflow)?;
    if length > MAX_IMAGE_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    let mut bytes = [0u8; MAX_IMAGE_BYTES];
    bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    patch_u16(&mut bytes, 16, 2)?;
    patch_u16(&mut bytes, 18, 62)?;
    patch_u32(&mut bytes, 20, 1)?;
    patch_u64(
        &mut bytes,
        24,
        IMAGE_BASE
            .checked_add(PAYLOAD_OFFSET as u64)
            .and_then(|value| value.checked_add(linked.entry_offset as u64))
            .ok_or(LinkerError::OffsetOverflow)?,
    )?;
    patch_u64(&mut bytes, 32, 64)?;
    patch_u16(&mut bytes, 52, 64)?;
    patch_u16(&mut bytes, 54, 56)?;
    patch_u16(
        &mut bytes,
        56,
        u16::try_from(program_count).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    let mut program = 64usize;
    write_elf_load_segment(
        &mut bytes,
        program,
        4,
        0,
        usize::try_from(IMAGE_BASE).map_err(|_| LinkerError::OffsetOverflow)?,
        header_bytes,
        header_bytes,
    )?;
    program += 56;
    write_elf_load_segment(
        &mut bytes,
        program,
        5,
        PAYLOAD_OFFSET,
        usize::try_from(IMAGE_BASE + PAYLOAD_OFFSET as u64)
            .map_err(|_| LinkerError::OffsetOverflow)?,
        linked.layout.text_length,
        linked.layout.text_length,
    )?;
    program += 56;
    if has_readonly {
        let offset = PAYLOAD_OFFSET
            .checked_add(linked.layout.readonly_offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        write_elf_load_segment(
            &mut bytes,
            program,
            4,
            offset,
            usize::try_from(IMAGE_BASE)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(offset)
                .ok_or(LinkerError::OffsetOverflow)?,
            linked.layout.readonly_length,
            linked.layout.readonly_length,
        )?;
        program += 56;
    }
    if has_writable {
        let offset = PAYLOAD_OFFSET
            .checked_add(linked.layout.writable_offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        let file_size = linked
            .length
            .checked_sub(linked.layout.writable_offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        let memory_size = linked
            .memory_length
            .checked_sub(linked.layout.writable_offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        write_elf_load_segment(
            &mut bytes,
            program,
            6,
            offset,
            usize::try_from(IMAGE_BASE)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(offset)
                .ok_or(LinkerError::OffsetOverflow)?,
            file_size,
            memory_size,
        )?;
        program += 56;
    }
    if has_tls {
        let offset = PAYLOAD_OFFSET
            .checked_add(linked.layout.tls_offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        let address = usize::try_from(IMAGE_BASE)
            .map_err(|_| LinkerError::OffsetOverflow)?
            .checked_add(offset)
            .ok_or(LinkerError::OffsetOverflow)?;
        write_elf_program_segment(
            &mut bytes,
            program,
            7,
            4,
            offset,
            address,
            linked.layout.tls_file_length,
            linked.layout.tls_memory_length,
            linked.layout.tls_alignment,
        )?;
    }
    copy_at(&mut bytes, PAYLOAD_OFFSET, linked.bytes())?;
    Ok(ElfImage { bytes, length })
}

fn validate_selected_definition_set(
    inputs: &[ElfSelectedObject<'_, '_>],
) -> Result<(), LinkerError> {
    for (input_index, input) in inputs.iter().enumerate() {
        for (definition_index, definition) in input.definitions.definitions().iter().enumerate() {
            if definition.binding != ElfSelectedSymbolBinding::Global {
                continue;
            }
            if definition.section_index == 0xfff2 {
                validate_elf_common_shape(definition.size, definition.offset)?;
                continue;
            }
            for earlier in &inputs[..input_index] {
                if earlier.definitions.definitions().iter().any(|candidate| {
                    candidate.name == definition.name
                        && candidate.binding == ElfSelectedSymbolBinding::Global
                        && candidate.section_index != 0xfff2
                }) {
                    return Err(LinkerError::DuplicateSymbol);
                }
            }
            if input.definitions.definitions()[..definition_index]
                .iter()
                .any(|candidate| {
                    candidate.name == definition.name
                        && candidate.binding == ElfSelectedSymbolBinding::Global
                        && candidate.section_index != 0xfff2
                })
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
    }
    Ok(())
}

fn resolve_selected_definition<'data, 'view, 'inputs>(
    inputs: &'inputs [ElfSelectedObject<'data, 'view>],
    symbol: &str,
) -> Result<Option<(usize, &'inputs ElfSelectedDefinition<'data>)>, LinkerError> {
    let mut weak = None;
    let mut common = None;
    let mut strong = None;
    for (input_index, input) in inputs.iter().enumerate() {
        for definition in input.definitions.definitions() {
            if definition.name != symbol {
                continue;
            }
            if definition.section_index == 0xfff2 {
                validate_elf_common_shape(definition.size, definition.offset)?;
                if common.is_none() {
                    common = Some((input_index, definition));
                }
                continue;
            }
            match definition.binding {
                ElfSelectedSymbolBinding::Global
                    if strong.replace((input_index, definition)).is_some() =>
                {
                    return Err(LinkerError::DuplicateSymbol);
                }
                ElfSelectedSymbolBinding::Global => {}
                ElfSelectedSymbolBinding::Weak if weak.is_none() => {
                    weak = Some((input_index, definition))
                }
                ElfSelectedSymbolBinding::Weak => {}
            }
        }
    }
    Ok(strong.or(common).or(weak))
}

fn validate_elf_common_shape(size: usize, alignment: usize) -> Result<(), LinkerError> {
    if size == 0 || alignment == 0 || !alignment.is_power_of_two() || alignment > 0x1000 {
        return Err(LinkerError::UnsupportedElf);
    }
    Ok(())
}

fn selected_common_layout_offset(
    layout: &ElfSelectedLayout,
    inputs: &[ElfSelectedObject<'_, '_>],
    symbol: &str,
) -> Result<usize, LinkerError> {
    for common in layout.commons() {
        let definition = inputs[usize::from(common.input_index)]
            .definitions
            .definitions()
            .get(usize::from(common.definition_index))
            .ok_or(LinkerError::InvalidElf)?;
        if definition.name == symbol {
            return Ok(common.offset);
        }
    }
    Err(LinkerError::InvalidElf)
}

fn selected_elf_array_boundary(layout: &ElfSelectedLayout, symbol: &str) -> Option<usize> {
    match symbol {
        "__preinit_array_start" => Some(layout.preinitializer_start),
        "__preinit_array_end" => Some(layout.preinitializer_end),
        "__init_array_start" => Some(layout.initializer_start),
        "__init_array_end" => Some(layout.initializer_end),
        "__fini_array_start" => Some(layout.finalizer_start),
        "__fini_array_end" => Some(layout.finalizer_end),
        "__tls_image_start" if layout.tls_memory_length != 0 => Some(layout.tls_offset),
        "__tls_image_end" if layout.tls_memory_length != 0 => {
            layout.tls_offset.checked_add(layout.tls_memory_length)
        }
        _ => None,
    }
}

fn is_elf_array_boundary_symbol(symbol: &str) -> bool {
    matches!(
        symbol,
        "__preinit_array_start"
            | "__preinit_array_end"
            | "__init_array_start"
            | "__init_array_end"
            | "__fini_array_start"
            | "__fini_array_end"
            | "__tls_image_start"
            | "__tls_image_end"
    )
}

fn selected_section_layout_offset(
    layout: &ElfSelectedLayout,
    input_index: usize,
    section_index: u16,
) -> Result<usize, LinkerError> {
    layout
        .sections()
        .iter()
        .find(|section| {
            usize::from(section.input_index) == input_index
                && section.section_index == section_index
        })
        .map(|section| section.offset)
        .ok_or(LinkerError::InvalidElf)
}

fn relax_selected_gotpcrel<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    place: usize,
) -> Result<(), LinkerError> {
    if place >= 2 && output.get(place - 2) == Some(&0xff) {
        output[place - 2] = 0x90;
        output[place - 1] = match output[place - 1] {
            0x15 => 0xe8,
            0x25 => 0xe9,
            _ => return Err(LinkerError::UnsupportedElf),
        };
        return Ok(());
    }
    if place >= 3
        && output.get(place - 3) == Some(&0x48)
        && output.get(place - 2) == Some(&0x8b)
        && output
            .get(place - 1)
            .is_some_and(|modrm| modrm & 0xc7 == 0x05)
    {
        output[place - 2] = 0x8d;
        return Ok(());
    }
    Err(LinkerError::UnsupportedElf)
}

impl<'a> ElfSelectedRelocations<'a> {
    pub fn relocations(&self) -> &[ElfSelectedRelocation<'a>] {
        &self.relocations[..self.length]
    }
}

impl<'a> ElfSelectedSections<'a> {
    pub fn sections(&self) -> &[ElfSelectedSection<'a>] {
        &self.sections[..self.length]
    }
}

impl ElfSectionSelection {
    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.length]
    }
}

/// Decodes only the content sections admitted by a prior reachability pass.
/// Section names classify representation; the selection remains the authority
/// for which sections may enter later relocation and layout stages.
pub fn decode_x86_64_elf_selected_sections<'a>(
    object: &'a [u8],
    selection: &ElfSectionSelection,
) -> Result<ElfSelectedSections<'a>, LinkerError> {
    if selection.object_address != object.as_ptr() as usize
        || selection.object_length != object.len()
    {
        return Err(LinkerError::InvalidElf);
    }
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || read_u16_elf(object, 18)? != 62
        || read_u16_elf(object, 58)? != 64
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let names_index = usize::from(read_u16_elf(object, 62)?);
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) || names_index >= section_count {
        return Err(LinkerError::UnsupportedElf);
    }
    let names_header = elf_section_header(section_offset, section_count, names_index)?;
    if read_u32_elf(object, names_header + 4)? != 3 {
        return Err(LinkerError::InvalidElf);
    }
    let names = elf_section_contents(object, section_offset, section_count, names_index)?;
    let empty = ElfSelectedSection {
        index: 0,
        name: "",
        kind: ElfSectionKind::Text,
        bytes: &[],
        size: 0,
        alignment: 1,
    };
    let mut decoded = ElfSelectedSections {
        sections: [empty; MAX_LINK_INPUTS],
        length: 0,
    };
    let mut previous = 0usize;
    for &raw_index in selection.indices() {
        let index = usize::from(raw_index);
        if index == 0 || index >= section_count || (decoded.length != 0 && index <= previous) {
            return Err(LinkerError::InvalidElf);
        }
        previous = index;
        let header = elf_section_header(section_offset, section_count, index)?;
        let section_type = read_u32_elf(object, header + 4)?;
        let flags = read_u64_elf(object, header + 8)?;
        let name_offset = usize::try_from(read_u32_elf(object, header)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let name = elf_string(names, name_offset)?;
        let size = to_usize_elf(read_u64_elf(object, header + 32)?)?;
        let alignment = to_usize_elf(read_u64_elf(object, header + 48)?)?;
        if alignment == 0 || !alignment.is_power_of_two() || alignment > 4096 {
            return Err(LinkerError::UnsupportedElf);
        }
        let kind = if (name == ".text" || name.starts_with(".text."))
            && section_type == 1
            && flags & 0x6 == 0x6
            && flags & 0x1 == 0
        {
            ElfSectionKind::Text
        } else if (name == ".rodata"
            || name.starts_with(".rodata.")
            || name == ".gcc_except_table"
            || name.starts_with(".gcc_except_table."))
            && section_type == 1
            && flags & 0x2 == 0x2
            && flags & 0x5 == 0
        {
            ElfSectionKind::ReadonlyData
        } else if (name == ".data" || name.starts_with(".data."))
            && section_type == 1
            && flags & 0x3 == 0x3
            && flags & 0x4 == 0
        {
            ElfSectionKind::WritableData
        } else if (name == ".tdata" || name.starts_with(".tdata."))
            && section_type == 1
            && flags & 0x403 == 0x403
            && flags & !0x403 == 0
        {
            ElfSectionKind::InitializedTls
        } else if matches!(section_type, 14..=16) {
            if flags & 3 != 3
                || flags & !0x20_0003 != 0
                || alignment != 8
                || size % 8 != 0
                || !matches!(read_u64_elf(object, header + 56)?, 0 | 8)
            {
                return Err(LinkerError::UnsupportedElf);
            }
            let kind = match section_type {
                14 => ElfSectionKind::InitializerArray,
                15 => ElfSectionKind::FinalizerArray,
                16 => ElfSectionKind::PreInitializerArray,
                _ => return Err(LinkerError::UnsupportedElf),
            };
            elf_array_section_priority(name, kind)?;
            kind
        } else if (name == ".bss" || name.starts_with(".bss."))
            && section_type == 8
            && flags & 0x3 == 0x3
            && flags & 0x4 == 0
        {
            ElfSectionKind::ZeroedData
        } else if (name == ".tbss" || name.starts_with(".tbss."))
            && section_type == 8
            && flags & 0x403 == 0x403
            && flags & !0x403 == 0
        {
            ElfSectionKind::ZeroedTls
        } else if name == ".eh_frame" && section_type == 0x7000_0001 && flags & 0x2 == 0x2 {
            ElfSectionKind::Unwind
        } else {
            return Err(LinkerError::UnsupportedElf);
        };
        let bytes = if section_type == 8 {
            &object[0..0]
        } else {
            let contents = elf_section_contents(object, section_offset, section_count, index)?;
            if contents.len() != size {
                return Err(LinkerError::InvalidElf);
            }
            contents
        };
        decoded.sections[decoded.length] = ElfSelectedSection {
            index: raw_index,
            name,
            kind,
            bytes,
            size,
            alignment,
        };
        decoded.length += 1;
    }
    Ok(decoded)
}

/// Decodes RELA records whose destination section was admitted by the exact
/// reachability selection. Local targets retain section identity for layout;
/// undefined names remain unresolved for the cross-object symbol pass.
pub fn decode_x86_64_elf_selected_relocations<'a>(
    object: &'a [u8],
    selection: &ElfSectionSelection,
) -> Result<ElfSelectedRelocations<'a>, LinkerError> {
    let selected_sections = decode_x86_64_elf_selected_sections(object, selection)?;
    decode_x86_64_elf_selected_relocations_from_sections(object, selection, &selected_sections)
}

pub fn decode_x86_64_elf_selected_relocations_from_sections<'a>(
    object: &'a [u8],
    selection: &ElfSectionSelection,
    selected_sections: &ElfSelectedSections<'a>,
) -> Result<ElfSelectedRelocations<'a>, LinkerError> {
    if selection.object_address != object.as_ptr() as usize
        || selection.object_length != object.len()
    {
        return Err(LinkerError::InvalidElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let mut selected = [false; MAX_ELF_SECTIONS];
    let mut selected_sizes = [0usize; MAX_ELF_SECTIONS];
    for section in selected_sections.sections() {
        let index = usize::from(section.index);
        selected[index] = true;
        selected_sizes[index] = section.size;
    }
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? == 2 && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    if read_u64_elf(object, symbols_header + 56)? != 24 {
        return Err(LinkerError::UnsupportedElf);
    }
    let strings_index = usize::try_from(read_u32_elf(object, symbols_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    if strings_index >= section_count {
        return Err(LinkerError::InvalidElf);
    }
    let strings_header = elf_section_header(section_offset, section_count, strings_index)?;
    if read_u32_elf(object, strings_header + 4)? != 3 {
        return Err(LinkerError::InvalidElf);
    }
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    let empty = ElfSelectedRelocation {
        section_index: 0,
        offset: 0,
        kind: ElfSelectedRelocationKind::PcRelative32,
        target: ElfSelectedRelocationTarget::Absolute(0),
        addend: 0,
    };
    let mut decoded = ElfSelectedRelocations {
        relocations: [empty; MAX_LINK_RELOCATIONS],
        length: 0,
    };
    for relocation_index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, relocation_index)?;
        if read_u32_elf(object, header + 4)? != 4 {
            continue;
        }
        let destination = usize::try_from(read_u32_elf(object, header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if destination >= section_count || !selected[destination] {
            continue;
        }
        if usize::try_from(read_u32_elf(object, header + 40)?)
            .map_err(|_| LinkerError::OffsetOverflow)?
            != symbols_index
            || read_u64_elf(object, header + 56)? != 24
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let records =
            elf_section_contents(object, section_offset, section_count, relocation_index)?;
        if records.len() % 24 != 0 {
            return Err(LinkerError::InvalidElf);
        }
        for record in records.chunks_exact(24) {
            if decoded.length == decoded.relocations.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let offset = to_usize_elf(read_u64_elf(record, 0)?)?;
            let info = read_u64_elf(record, 8)?;
            let raw_kind =
                u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)?;
            let (kind, width) = match raw_kind {
                1 => (ElfSelectedRelocationKind::Absolute64, 8),
                10 => (ElfSelectedRelocationKind::Absolute32, 4),
                11 => (ElfSelectedRelocationKind::SignedAbsolute32, 4),
                2 => (ElfSelectedRelocationKind::PcRelative32, 4),
                4 => (ElfSelectedRelocationKind::PltRelative32, 4),
                9 => (ElfSelectedRelocationKind::GotPcRelative32, 4),
                23 => (ElfSelectedRelocationKind::ThreadPointerOffset32, 4),
                _ => return Err(LinkerError::UnsupportedElf),
            };
            offset
                .checked_add(width)
                .filter(|end| *end <= selected_sizes[destination])
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            let symbol_index = to_usize_elf(info >> 32)?;
            let symbol_offset = symbol_index
                .checked_mul(24)
                .ok_or(LinkerError::OffsetOverflow)?;
            symbols
                .get(symbol_offset..symbol_offset + 24)
                .ok_or(LinkerError::InvalidElf)?;
            let target_section = usize::from(read_u16_elf(symbols, symbol_offset + 6)?);
            let value = read_u64_elf(symbols, symbol_offset + 8)?;
            let target = if target_section == 0 {
                let name_offset = usize::try_from(read_u32_elf(symbols, symbol_offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                if name_offset == 0 || value != 0 {
                    return Err(LinkerError::UnsupportedElf);
                }
                ElfSelectedRelocationTarget::Symbol(elf_string(strings, name_offset)?)
            } else if target_section == 0xfff1 {
                ElfSelectedRelocationTarget::Absolute(value)
            } else if target_section == 0xfff2 {
                let name_offset = usize::try_from(read_u32_elf(symbols, symbol_offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let size = to_usize_elf(read_u64_elf(symbols, symbol_offset + 16)?)?;
                validate_elf_common_shape(size, to_usize_elf(value)?)?;
                if name_offset == 0 {
                    return Err(LinkerError::EmptySymbol);
                }
                ElfSelectedRelocationTarget::Symbol(elf_string(strings, name_offset)?)
            } else if target_section < section_count && selected[target_section] {
                let target_size = selected_sizes[target_section];
                let offset = to_usize_elf(value)?;
                if offset > target_size {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfSelectedRelocationTarget::Section {
                    index: u16::try_from(target_section)
                        .map_err(|_| LinkerError::TooManyElfSections)?,
                    offset,
                }
            } else {
                return Err(LinkerError::InvalidElf);
            };
            decoded.relocations[decoded.length] = ElfSelectedRelocation {
                section_index: u16::try_from(destination)
                    .map_err(|_| LinkerError::TooManyElfSections)?,
                offset,
                kind,
                target,
                addend: read_i64_elf(record, 16)?,
            };
            decoded.length += 1;
        }
    }
    Ok(decoded)
}

/// Decodes externally resolvable definitions that reside in selected
/// sections. Local symbols remain section-relative relocation targets and do
/// not enter the cross-object namespace.
pub fn decode_x86_64_elf_selected_definitions<'a>(
    object: &'a [u8],
    selection: &ElfSectionSelection,
) -> Result<ElfSelectedDefinitions<'a>, LinkerError> {
    let selected_sections = decode_x86_64_elf_selected_sections(object, selection)?;
    decode_x86_64_elf_selected_definitions_from_sections(object, selection, &selected_sections)
}

pub fn decode_x86_64_elf_selected_definitions_from_sections<'a>(
    object: &'a [u8],
    selection: &ElfSectionSelection,
    selected_sections: &ElfSelectedSections<'a>,
) -> Result<ElfSelectedDefinitions<'a>, LinkerError> {
    if selection.object_address != object.as_ptr() as usize
        || selection.object_length != object.len()
    {
        return Err(LinkerError::InvalidElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let mut selected_sizes = [None; MAX_ELF_SECTIONS];
    for section in selected_sections.sections() {
        selected_sizes[usize::from(section.index)] = Some(section.size);
    }
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? == 2 && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    if read_u64_elf(object, symbols_header + 56)? != 24 {
        return Err(LinkerError::UnsupportedElf);
    }
    let strings_index = usize::try_from(read_u32_elf(object, symbols_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    if strings_index >= section_count {
        return Err(LinkerError::InvalidElf);
    }
    let strings_header = elf_section_header(section_offset, section_count, strings_index)?;
    if read_u32_elf(object, strings_header + 4)? != 3 {
        return Err(LinkerError::InvalidElf);
    }
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    let empty = ElfSelectedDefinition {
        name: "",
        section_index: 0,
        offset: 0,
        size: 0,
        binding: ElfSelectedSymbolBinding::Global,
        visibility: ElfSelectedSymbolVisibility::Default,
        kind: ElfSelectedSymbolKind::Unspecified,
    };
    let mut decoded = ElfSelectedDefinitions {
        definitions: [empty; MAX_LINK_DEFINITIONS],
        length: 0,
    };
    for record in symbols[24..].chunks_exact(24) {
        let section = usize::from(read_u16_elf(record, 6)?);
        let common = section == 0xfff2;
        let section_size = if common {
            None
        } else {
            let Some(section_size) = selected_sizes.get(section).copied().flatten() else {
                continue;
            };
            Some(section_size)
        };
        let info = *record.get(4).ok_or(LinkerError::InvalidElf)?;
        let binding = match info >> 4 {
            0 => continue,
            1 => ElfSelectedSymbolBinding::Global,
            2 => ElfSelectedSymbolBinding::Weak,
            _ => return Err(LinkerError::UnsupportedElf),
        };
        let kind = match info & 0xf {
            0 => ElfSelectedSymbolKind::Unspecified,
            1 => ElfSelectedSymbolKind::Object,
            2 => ElfSelectedSymbolKind::Function,
            6 => ElfSelectedSymbolKind::ThreadLocal,
            _ => return Err(LinkerError::UnsupportedElf),
        };
        let visibility = match *record.get(5).ok_or(LinkerError::InvalidElf)? & 0x3 {
            0 => ElfSelectedSymbolVisibility::Default,
            2 => ElfSelectedSymbolVisibility::Hidden,
            _ => return Err(LinkerError::UnsupportedElf),
        };
        let name_offset =
            usize::try_from(read_u32_elf(record, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        if name_offset == 0 {
            return Err(LinkerError::EmptySymbol);
        }
        let name = elf_string(strings, name_offset)?;
        validate_symbol(name)?;
        let offset = to_usize_elf(read_u64_elf(record, 8)?)?;
        let size = to_usize_elf(read_u64_elf(record, 16)?)?;
        if common {
            validate_elf_common_shape(size, offset)?;
            if kind == ElfSelectedSymbolKind::Function {
                return Err(LinkerError::UnsupportedElf);
            }
        } else {
            let section_size = section_size.ok_or(LinkerError::InvalidElf)?;
            offset
                .checked_add(size)
                .filter(|end| *end <= section_size)
                .ok_or(LinkerError::InvalidElf)?;
        }
        if decoded.length == decoded.definitions.len() {
            return Err(LinkerError::TooManyDefinitions);
        }
        decoded.definitions[decoded.length] = ElfSelectedDefinition {
            name,
            section_index: u16::try_from(section).map_err(|_| LinkerError::TooManyElfSections)?,
            offset,
            size,
            binding,
            visibility,
            kind,
        };
        decoded.length += 1;
    }
    Ok(decoded)
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
    if inputs.len() > MAX_LINK_FRAGMENTS || inputs.len() != archive_member.len() {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;
    let mut selected = [false; MAX_LINK_FRAGMENTS];
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
                target: inputs[candidate].symbol_target,
            })
            .chain(inputs[candidate].additional_definitions.iter().copied())
            .filter(|definition| definition_is_global(definition.target))
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
        indices: [0; MAX_LINK_FRAGMENTS],
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
    if inputs.len() > MAX_LINK_FRAGMENTS {
        return Err(LinkerError::TooManyInputs);
    }
    let mut archive_member = [0u16; MAX_LINK_FRAGMENTS];
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
    if inputs.len() > MAX_LINK_FRAGMENTS
        || inputs.len() != archive_group.len()
        || inputs.len() != archive_member.len()
    {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;
    let mut selected = [false; MAX_LINK_FRAGMENTS];
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
                let exact_section_needed = core::iter::once(inputs[candidate].symbol_target)
                    .chain(
                        inputs[candidate]
                            .additional_definitions
                            .iter()
                            .map(|definition| definition.target),
                    )
                    .filter_map(definition_coff_section_identity)
                    .any(|identity| coff_section_is_referenced(inputs, &selected, identity));
                if exact_section_needed {
                    selected[candidate] = true;
                    changed = true;
                    continue;
                }
                let needed = core::iter::once(LinkDefinition {
                    symbol: inputs[candidate].symbol,
                    target: inputs[candidate].symbol_target,
                })
                .chain(inputs[candidate].additional_definitions.iter().copied())
                .filter(|definition| definition_is_global(definition.target))
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
        indices: [0; MAX_LINK_FRAGMENTS],
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

fn definition_coff_section_identity(target: LinkDefinitionTarget) -> Option<CoffSectionIdentity> {
    match target {
        LinkDefinitionTarget::CoffTextSection { identity, .. }
        | LinkDefinitionTarget::CoffSection { identity, .. } => Some(identity),
        LinkDefinitionTarget::Text(_) | LinkDefinitionTarget::ReadonlyData(_) => None,
    }
}

fn coff_section_is_referenced(
    inputs: &[LinkInput<'_, '_, '_>],
    selected: &[bool; MAX_LINK_FRAGMENTS],
    identity: CoffSectionIdentity,
) -> bool {
    inputs.iter().zip(selected).any(|(input, selected)| {
        *selected
            && input.relocations.iter().any(|relocation| {
                matches!(
                    relocation.target,
                    LinkRelocationTarget::CoffSection {
                        identity: target,
                        ..
                    } | LinkRelocationTarget::PeTlsSection {
                        identity: target,
                        ..
                    } if target == identity
                )
            })
    })
}

fn symbol_is_defined(
    inputs: &[LinkInput<'_, '_, '_>],
    selected: &[bool; MAX_LINK_FRAGMENTS],
    symbol: &str,
) -> bool {
    inputs
        .iter()
        .enumerate()
        .any(|(index, input)| selected[index] && input_definition_target(input, symbol).is_some())
}

fn input_definition_target(
    input: &LinkInput<'_, '_, '_>,
    symbol: &str,
) -> Option<LinkDefinitionTarget> {
    if input.symbol == symbol {
        return definition_is_global(input.symbol_target).then_some(input.symbol_target);
    }
    input
        .additional_definitions
        .iter()
        .find(|definition| definition.symbol == symbol)
        .and_then(|definition| definition_is_global(definition.target).then_some(definition.target))
}

fn definition_is_global(target: LinkDefinitionTarget) -> bool {
    !matches!(
        target,
        LinkDefinitionTarget::CoffTextSection { .. }
            | LinkDefinitionTarget::CoffSection { .. }
    )
}

fn symbol_is_referenced(
    inputs: &[LinkInput<'_, '_, '_>],
    selected: &[bool; MAX_LINK_FRAGMENTS],
    symbol: &str,
) -> bool {
    inputs.iter().enumerate().any(|(index, input)| {
        selected[index]
            && input.relocations.iter().any(|relocation| {
                matches!(
                    relocation.target,
                    LinkRelocationTarget::Symbol(target)
                        | LinkRelocationTarget::GotPcRelativeSymbol(target)
                        | LinkRelocationTarget::RequiredSymbol(target)
                        if target == symbol
                )
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
        target: LinkDefinitionTarget::Text(0),
    }; MAX_LINK_DEFINITIONS];
    let decoded =
        decode_x86_64_coff_with_definitions(object, relocation_storage, &mut definitions)?;
    if !decoded.additional_definitions.is_empty() {
        return Err(LinkerError::UnsupportedCoff);
    }
    Ok(LinkInput {
        symbol: decoded.symbol,
        symbol_target: decoded.symbol_target,
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
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
    }
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
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
        if (name.starts_with(".data$") || name.starts_with(".bss$"))
            && read_u32(object, header + 16)? != 0
        {
            count = count.checked_add(1).ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(count)
}

pub fn x86_64_coff_readonly_absolute_relocation_count(object: &[u8]) -> Result<usize, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
        if name.starts_with(".rdata$.refptr.") && read_u32(object, header + 16)? != 0 {
            count = count.checked_add(1).ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(count)
}

pub fn decode_x86_64_coff_readonly_absolute_relocation<'a>(
    object: &'a [u8],
    relocation_index: usize,
    readonly_owner: &'a str,
) -> Result<PeReadonlyAbsoluteRelocation<'a>, LinkerError> {
    validate_symbol(readonly_owner)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    let mut readonly_start = None;
    let mut readonly_end = None;
    let mut selected = None;
    let mut ordinal = 0usize;
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
        if size == 0 || !(name == ".rdata" || name.starts_with(".rdata$")) {
            continue;
        }
        let raw = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let end = raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?;
        object.get(raw..end).ok_or(LinkerError::InvalidCoff)?;
        match readonly_end {
            Some(previous_end) if previous_end > raw => return Err(LinkerError::UnsupportedCoff),
            _ => readonly_end = Some(end),
        }
        let start = *readonly_start.get_or_insert(raw);
        if name.starts_with(".rdata$.refptr.") {
            if ordinal == relocation_index {
                if size != 8 || read_u16(object, header + 32)? != 1 {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let relocation = usize::try_from(read_u32(object, header + 24)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                object
                    .get(relocation..relocation + 10)
                    .ok_or(LinkerError::InvalidCoff)?;
                if read_u32(object, relocation)? != 0 || read_u16(object, relocation + 8)? != 1 {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let target_index = usize::try_from(read_u32(object, relocation + 4)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                if target_index >= symbol_count {
                    return Err(LinkerError::InvalidCoff);
                }
                let target = symbol_offset
                    .checked_add(
                        target_index
                            .checked_mul(18)
                            .ok_or(LinkerError::OffsetOverflow)?,
                    )
                    .ok_or(LinkerError::OffsetOverflow)?;
                if read_i16(object, target + 12)? != 0
                    || *object.get(target + 16).ok_or(LinkerError::InvalidCoff)? != 2
                {
                    return Err(LinkerError::UnsupportedCoff);
                }
                let initial = read_u64_coff(
                    object
                        .get(raw..raw + size)
                        .ok_or(LinkerError::InvalidCoff)?,
                    0,
                )?;
                selected = Some(PeReadonlyAbsoluteRelocation {
                    readonly_owner,
                    readonly_identity: None,
                    readonly_offset: raw.checked_sub(start).ok_or(LinkerError::OffsetOverflow)?,
                    target_symbol: coff_symbol_name(object, target, symbols_end, string_size)?,
                    target_identity: None,
                    target_offset: 0,
                    addend: i64::from_le_bytes(initial.to_le_bytes()),
                    kind: PeReadonlyRelocationKind::Address64,
                });
            }
            ordinal += 1;
        }
    }
    selected.ok_or(LinkerError::InvalidCoff)
}

pub fn decode_x86_64_coff_readonly_absolute_relocation_for_fragment(
    object: &[u8],
    relocation_index: usize,
) -> Result<PeReadonlyAbsoluteRelocation<'_>, LinkerError> {
    let section_count = usize::from(read_u16(object, 2)?);
    let symbol_offset =
        usize::try_from(read_u32(object, 8)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbol_count =
        usize::try_from(read_u32(object, 12)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let strings_offset = symbol_offset
        .checked_add(
            symbol_count
                .checked_mul(18)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    let string_size = usize::try_from(read_u32(object, strings_offset)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let mut ordinal = 0usize;
    for section in 0..section_count {
        let header = 20usize + section * 40;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            strings_offset,
            string_size,
        )?;
        if !name.starts_with(".rdata$.refptr.") || read_u32(object, header + 16)? == 0 {
            continue;
        }
        if ordinal == relocation_index {
            let selected_section =
                i16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
            let mut owner = None;
            let mut symbol_index = 0usize;
            while symbol_index < symbol_count {
                let symbol = symbol_offset + symbol_index * 18;
                let auxiliary =
                    usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
                if read_i16(object, symbol + 12)? == selected_section
                    && *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? == 2
                    && read_u32(object, symbol + 8)? == 0
                {
                    let candidate = coff_symbol_name(object, symbol, strings_offset, string_size)?;
                    if owner.replace(candidate).is_some() {
                        return Err(LinkerError::UnsupportedCoff);
                    }
                }
                symbol_index = symbol_index
                    .checked_add(auxiliary + 1)
                    .ok_or(LinkerError::OffsetOverflow)?;
            }
            let owner = owner.ok_or(LinkerError::UnsupportedCoff)?;
            let decoded =
                decode_x86_64_coff_readonly_absolute_relocation(object, relocation_index, owner)?;
            return Ok(PeReadonlyAbsoluteRelocation {
                readonly_owner: decoded.readonly_owner,
                readonly_identity: None,
                readonly_offset: 0,
                target_symbol: decoded.target_symbol,
                target_identity: None,
                target_offset: 0,
                addend: decoded.addend,
                kind: decoded.kind,
            });
        }
        ordinal += 1;
    }
    Err(LinkerError::InvalidCoff)
}

/// Decodes every AMD64 absolute relocation whose field belongs to a selected
/// read-only COMDAT. Standalone sections own their fields directly;
/// associative sections use the text root's external symbol and the exact raw
/// span used by text-fragment decoding. The prepared inventory binds all
/// association and selection decisions to this exact object.
fn coff_external_section_owner<'a>(
    object: &'a [u8],
    symbol_offset: usize,
    symbol_count: usize,
    symbols_end: usize,
    string_size: usize,
    requested_section: usize,
) -> Result<Option<&'a str>, LinkerError> {
    let requested = i16::try_from(requested_section).map_err(|_| LinkerError::OffsetOverflow)?;
    let mut owner = None;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let symbol = symbol_offset
            .checked_add(
                symbol_index
                    .checked_mul(18)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        if read_i16(object, symbol + 12)? == requested
            && *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? == 2
            && read_u32(object, symbol + 8)? == 0
            && owner.is_none()
        {
            owner = Some(coff_symbol_name(object, symbol, symbols_end, string_size)?);
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(owner)
}

fn coff_associative_readonly_start_for_root(
    object: &[u8],
    inventory: &CoffComdatSections<'_>,
    symbols_end: usize,
    string_size: usize,
    root: u16,
) -> Result<Option<usize>, LinkerError> {
    let section_count = usize::from(read_u16(object, 2)?);
    let mut start = None;
    for section in 0..section_count {
        let section_number = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        let Some(metadata) = inventory.section(section_number) else {
            continue;
        };
        if metadata.selection != CoffTextComdatSelection::Associative
            || inventory.root_section(section_number) != Some(root)
        {
            continue;
        }
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
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if size == 0 || !(name == ".rdata" || name.starts_with(".rdata$")) {
            continue;
        }
        let raw = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        object
            .get(raw..raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::InvalidCoff)?;
        start = Some(start.map_or(raw, |current| core::cmp::min(current, raw)));
    }
    Ok(start)
}

pub fn decode_x86_64_coff_readonly_absolute_relocations_from_inventory<'a>(
    object: &'a [u8],
    inventory: &CoffComdatSections<'_>,
) -> Result<PeReadonlyAbsoluteRelocations<'a>, LinkerError> {
    decode_x86_64_coff_readonly_absolute_relocations_for_object(object, inventory, None)
}

pub fn decode_x86_64_coff_readonly_absolute_relocations_with_section_identities_from_inventory<
    'a,
>(
    object: &'a [u8],
    inventory: &CoffComdatSections<'_>,
    object_identity: u16,
) -> Result<PeReadonlyAbsoluteRelocations<'a>, LinkerError> {
    CoffSectionIdentity::new(object_identity, 1)?;
    decode_x86_64_coff_readonly_absolute_relocations_for_object(
        object,
        inventory,
        Some(object_identity),
    )
}

fn decode_x86_64_coff_readonly_absolute_relocations_for_object<'a>(
    object: &'a [u8],
    inventory: &CoffComdatSections<'_>,
    object_identity: Option<u16>,
) -> Result<PeReadonlyAbsoluteRelocations<'a>, LinkerError> {
    inventory.validate_object(object)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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

    let empty = PeReadonlyAbsoluteRelocation {
        readonly_owner: "unused",
        readonly_identity: None,
        readonly_offset: 0,
        target_symbol: "unused",
        target_identity: None,
        target_offset: 0,
        addend: 0,
        kind: PeReadonlyRelocationKind::Address64,
    };
    let mut decoded = PeReadonlyAbsoluteRelocations {
        relocations: [empty; MAX_PE_READONLY_RELOCATIONS],
        length: 0,
    };
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
        let section_number = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        let Some(metadata) = inventory.section(section_number) else {
            continue;
        };
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if size == 0 || !(name == ".rdata" || name.starts_with(".rdata$")) {
            continue;
        }
        let raw = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let (owner_section, readonly_base) =
            if metadata.selection == CoffTextComdatSelection::Associative {
                let root = inventory
                    .root_section(section_number)
                    .ok_or(LinkerError::InvalidCoffAssociation)?;
                let Some(start) = coff_associative_readonly_start_for_root(
                    object,
                    inventory,
                    symbols_end,
                    string_size,
                    root,
                )?
                else {
                    continue;
                };
                (
                    usize::from(root),
                    raw.checked_sub(start).ok_or(LinkerError::OffsetOverflow)?,
                )
            } else {
                (section + 1, 0)
            };
        let owner = if object_identity.is_some() {
            name
        } else {
            coff_external_section_owner(
                object,
                symbol_offset,
                symbol_count,
                symbols_end,
                string_size,
                owner_section,
            )?
            .ok_or(LinkerError::UnsupportedCoffSymbol)?
        };
        let contents = object
            .get(raw..raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::InvalidCoff)?;
        let relocation_count = usize::from(read_u16(object, header + 32)?);
        let relocation_start = usize::try_from(read_u32(object, header + 24)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let relocation_end = relocation_start
            .checked_add(
                relocation_count
                    .checked_mul(10)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        object
            .get(relocation_start..relocation_end)
            .ok_or(LinkerError::InvalidCoff)?;
        for index in 0..relocation_count {
            if decoded.length == MAX_PE_READONLY_RELOCATIONS {
                return Err(LinkerError::TooManyRelocations);
            }
            let record = relocation_start + index * 10;
            let field = usize::try_from(read_u32(object, record)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let kind = match read_u16(object, record + 8)? {
                1 => PeReadonlyRelocationKind::Address64,
                3 => PeReadonlyRelocationKind::Address32NoBase,
                relocation @ 4..=9 => PeReadonlyRelocationKind::Relative32 {
                    trailing_bytes: u8::try_from(relocation - 4)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                },
                _ => return Err(LinkerError::UnsupportedCoffRelocation),
            };
            let field_width = match kind {
                PeReadonlyRelocationKind::Address64 => 8,
                PeReadonlyRelocationKind::Address32NoBase
                | PeReadonlyRelocationKind::Relative32 { .. } => 4,
            };
            field
                .checked_add(field_width)
                .filter(|end| *end <= contents.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            let target_index = usize::try_from(read_u32(object, record + 4)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if target_index >= symbol_count {
                return Err(LinkerError::InvalidCoff);
            }
            let target = symbol_offset
                .checked_add(
                    target_index
                        .checked_mul(18)
                        .ok_or(LinkerError::OffsetOverflow)?,
                )
                .ok_or(LinkerError::OffsetOverflow)?;
            let target_storage = *object.get(target + 16).ok_or(LinkerError::InvalidCoff)?;
            let target_section = read_i16(object, target + 12)?;
            let target_section_u16 = u16::try_from(target_section).ok();
            let target_is_projected = object_identity.is_some()
                && target_section_u16
                    .and_then(|section| inventory.section(section))
                    .is_some();
            if target_storage != 2 && !(target_storage == 3 && target_is_projected) {
                return Err(LinkerError::UnsupportedCoffRelocationTarget);
            }
            let target_identity = if target_storage == 3 {
                Some(CoffSectionIdentity::new(
                    object_identity.ok_or(LinkerError::UnsupportedCoffRelocationTarget)?,
                    target_section_u16.ok_or(LinkerError::UnsupportedCoffRelocationTarget)?,
                )?)
            } else {
                None
            };
            let target_value = usize::try_from(read_u32(object, target + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let addend = match kind {
                PeReadonlyRelocationKind::Address64 => {
                    i64::from_le_bytes(read_u64_coff(contents, field)?.to_le_bytes())
                }
                PeReadonlyRelocationKind::Address32NoBase
                | PeReadonlyRelocationKind::Relative32 { .. } => {
                    i64::from(read_i32(contents, field)?)
                }
            };
            decoded.relocations[decoded.length] = PeReadonlyAbsoluteRelocation {
                readonly_owner: owner,
                readonly_identity: object_identity
                    .map(|object_identity| {
                        CoffSectionIdentity::new(object_identity, section_number)
                    })
                    .transpose()?,
                readonly_offset: if object_identity.is_some() {
                    field
                } else {
                    readonly_base
                        .checked_add(field)
                        .ok_or(LinkerError::OffsetOverflow)?
                },
                target_symbol: coff_symbol_name(object, target, symbols_end, string_size)?,
                target_identity,
                target_offset: target_value,
                addend,
                kind,
            };
            decoded.length += 1;
        }
    }
    Ok(decoded)
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
    decode_x86_64_coff_writable_data_fragment_for_object(
        object,
        fragment_index,
        readonly_owner,
        None,
        relocation_storage,
    )
}

pub fn decode_x86_64_coff_writable_data_fragment_with_section_identities<
    'data,
    'relocations,
>(
    object: &'data [u8],
    fragment_index: usize,
    readonly_owner: &'data str,
    object_identity: u16,
    relocation_storage: &'relocations mut [PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<PeWritableData<'data, 'relocations>, LinkerError> {
    CoffSectionIdentity::new(object_identity, 1)?;
    decode_x86_64_coff_writable_data_fragment_for_object(
        object,
        fragment_index,
        readonly_owner,
        Some(object_identity),
        relocation_storage,
    )
}

fn decode_x86_64_coff_writable_data_fragment_for_object<'data, 'relocations>(
    object: &'data [u8],
    fragment_index: usize,
    readonly_owner: &'data str,
    object_identity: Option<u16>,
    relocation_storage: &'relocations mut [PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<PeWritableData<'data, 'relocations>, LinkerError> {
    validate_symbol(readonly_owner)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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

    let comdat_sections = if object_identity.is_some() {
        Some(inventory_x86_64_coff_comdat_sections(object)?)
    } else {
        None
    };
    let mut readonly_sections = CoffSectionSet::empty();
    let mut text_sections = CoffSectionSet::empty();
    let mut tls_sections = CoffSectionSet::empty();
    let mut writable_sections = CoffSectionSet::empty();
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
        if name == ".text" || name.starts_with(".text$") {
            text_sections.insert(section + 1)?;
        } else if name.starts_with(".tls$") {
            tls_sections.insert(section + 1)?;
        } else if name == ".rdata" || name.starts_with(".rdata$") {
            let raw = usize::try_from(read_u32(object, header + 20)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let end = raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?;
            object.get(raw..end).ok_or(LinkerError::InvalidCoff)?;
            readonly_sections.insert(section + 1)?;
            let section_number = u16::try_from(section + 1)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let projected = comdat_sections
                .as_ref()
                .is_some_and(|inventory| inventory.section(section_number).is_some());
            if !projected {
                readonly_span = Some(match readonly_span {
                    None => (raw, end),
                    Some((start, previous_end)) if previous_end <= raw => (start, end),
                    Some(_) => return Err(LinkerError::UnsupportedCoff),
                });
            }
        } else if name.starts_with(".data$") || name.starts_with(".bss$") {
            writable_sections.insert(section + 1)?;
            let characteristics = read_u32(object, header + 36)?;
            let zeroed = name.starts_with(".bss$");
            let expected = if zeroed { 0xc000_0080 } else { 0xc000_0040 };
            if characteristics & 0xe000_00e0 != expected {
                return Err(LinkerError::UnsupportedCoff);
            }
            if writable_ordinal == fragment_index {
                let bytes = if zeroed {
                    &object[0..0]
                } else {
                    let raw = usize::try_from(read_u32(object, header + 20)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?;
                    object
                        .get(raw..raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?)
                        .ok_or(LinkerError::InvalidCoff)?
                };
                writable = Some((
                    bytes,
                    if zeroed { size } else { 0 },
                    usize::try_from(read_u32(object, header + 24)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                    usize::from(read_u16(object, header + 32)?),
                    i16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?,
                    name,
                ));
            }
            writable_ordinal = writable_ordinal
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    let (bytes, zeroed_size, relocation_offset, relocation_count, writable_section, section_name) =
        writable.ok_or(LinkerError::InvalidCoff)?;
    let mut local_writable_symbol = None;
    let mut external_writable_symbol = None;
    let mut comdat_selection = PeWritableComdatSelection::None;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let symbol = symbol_offset + symbol_index * 18;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        let storage_class = *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)?;
        if read_i16(object, symbol + 12)? == writable_section
            && storage_class == 3
            && auxiliary == 1
            && read_u32(object, symbol + 8)? == 0
        {
            comdat_selection = match *object.get(symbol + 32).ok_or(LinkerError::InvalidCoff)? {
                0 => PeWritableComdatSelection::None,
                1 => PeWritableComdatSelection::NoDuplicates,
                2 => PeWritableComdatSelection::Any,
                _ => return Err(LinkerError::UnsupportedCoff),
            };
        }
        if read_i16(object, symbol + 12)? == writable_section
            && (storage_class == 2 || storage_class == 3)
            && auxiliary == 0
            && read_u32(object, symbol + 8)? == 0
        {
            let name = coff_symbol_name(object, symbol, symbols_end, string_size)?;
            let slot = if storage_class == 2 {
                &mut external_writable_symbol
            } else {
                &mut local_writable_symbol
            };
            if slot.replace(name).is_some() {
                return Err(LinkerError::UnsupportedCoff);
            }
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let writable_symbol = external_writable_symbol
        .or(local_writable_symbol)
        .unwrap_or(section_name);
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
        let relocation_target = if readonly_sections.contains(target_section_index) {
            let target_header = 20 + (target_section_index - 1) * 40;
            let target_size = usize::try_from(read_u32(object, target_header + 16)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let target_value = usize::try_from(read_u32(object, target + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let addend = read_u64_coff(bytes, field_offset)?;
            let addend = usize::try_from(addend).map_err(|_| LinkerError::OffsetOverflow)?;
            let target_section = u16::try_from(target_section_index)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let projected = comdat_sections
                .as_ref()
                .is_some_and(|inventory| inventory.section(target_section).is_some());
            if let Some(object_identity) = object_identity.filter(|_| projected) {
                let offset = target_value
                    .checked_add(addend)
                    .filter(|offset| *offset <= target_size)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                PeWritableRelocationTarget::CoffSection {
                    identity: CoffSectionIdentity::new(
                        object_identity,
                        target_section,
                    )?,
                    offset,
                }
            } else {
                let target_raw = usize::try_from(read_u32(object, target_header + 20)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let readonly_start = readonly_span.ok_or(LinkerError::UnsupportedCoff)?.0;
                let offset = target_raw
                    .checked_sub(readonly_start)
                    .and_then(|offset| offset.checked_add(target_value))
                    .and_then(|offset| offset.checked_add(addend))
                    .ok_or(LinkerError::OffsetOverflow)?;
                PeWritableRelocationTarget::Readonly {
                    owner: readonly_owner,
                    offset,
                }
            }
        } else if text_sections.contains(target_section_index) {
            let storage_class = *object.get(target + 16).ok_or(LinkerError::InvalidCoff)?;
            if (storage_class != 2 && storage_class != 3)
                || read_u64_coff(bytes, field_offset)? != 0
            {
                return Err(LinkerError::UnsupportedCoff);
            }
            PeWritableRelocationTarget::TextSymbol(coff_symbol_name(
                object,
                target,
                symbols_end,
                string_size,
            )?)
        } else if tls_sections.contains(target_section_index) {
            let object_identity = object_identity.ok_or(LinkerError::UnsupportedCoffTls)?;
            let target_header = 20 + (target_section_index - 1) * 40;
            let target_size = usize::try_from(read_u32(object, target_header + 16)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let target_value = usize::try_from(read_u32(object, target + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let addend = usize::try_from(read_u64_coff(bytes, field_offset)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let offset = target_value
                .checked_add(addend)
                .filter(|offset| *offset <= target_size)
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            PeWritableRelocationTarget::TlsSection {
                identity: CoffSectionIdentity::new(
                    object_identity,
                    u16::try_from(target_section_index)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                )?,
                offset,
            }
        } else if writable_sections.contains(target_section_index) {
            let storage_class = *object.get(target + 16).ok_or(LinkerError::InvalidCoff)?;
            if (storage_class != 2 && storage_class != 3)
                || read_u32(object, target + 8)? != 0
                || read_u64_coff(bytes, field_offset)? != 0
            {
                return Err(LinkerError::UnsupportedCoff);
            }
            PeWritableRelocationTarget::WritableSymbol(coff_symbol_name(
                object,
                target,
                symbols_end,
                string_size,
            )?)
        } else {
            return Err(LinkerError::UnsupportedCoff);
        };
        *slot = PeWritableRelocation {
            offset: field_offset,
            target: relocation_target,
        };
    }
    Ok(PeWritableData {
        symbol: writable_symbol,
        selection: comdat_selection,
        initialized: bytes,
        zeroed_size,
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
    decode_x86_64_coff_runtime_functions_for_object(object, None, record_storage)
}

pub fn decode_x86_64_coff_runtime_functions_with_section_identities<'data, 'records>(
    object: &'data [u8],
    object_identity: u16,
    record_storage: &'records mut [PeRuntimeFunction<'data>; MAX_PE_RUNTIME_FUNCTIONS],
) -> Result<&'records [PeRuntimeFunction<'data>], LinkerError> {
    CoffSectionIdentity::new(object_identity, 1)?;
    decode_x86_64_coff_runtime_functions_for_object(
        object,
        Some(object_identity),
        record_storage,
    )
}

fn decode_x86_64_coff_runtime_functions_for_object<'data, 'records>(
    object: &'data [u8],
    object_identity: Option<u16>,
    record_storage: &'records mut [PeRuntimeFunction<'data>; MAX_PE_RUNTIME_FUNCTIONS],
) -> Result<&'records [PeRuntimeFunction<'data>], LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    let comdat_sections = inventory_x86_64_coff_comdat_sections(object)?;

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
        let pdata_section = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        let pdata_name = name;
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
            return Err(LinkerError::UnsupportedCoffSection);
        }
        let relocation_offset = usize::try_from(read_u32(object, header + 24)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let relocation_count = usize::from(read_u16(object, header + 32)?);
        if relocation_count != records.len() / 4 {
            return Err(LinkerError::UnsupportedCoffRelocation);
        }
        for record_index in 0..records.len() / 12 {
            if record_count == record_storage.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let mut text_targets = [("", 0usize); 2];
            let mut text_sections = [0u16; 2];
            let mut text_section_names = [""; 2];
            let mut unwind_info = None;
            let mut unwind_section = None;
            let mut unwind_section_name = None;
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
                    return Err(LinkerError::UnsupportedCoffRelocation);
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
                    return Err(LinkerError::UnsupportedCoffRelocationTarget);
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
                        return Err(LinkerError::InvalidCoffAssociation);
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
                    text_sections[field] =
                        u16::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?;
                    text_section_names[field] = target_name;
                } else {
                    if !target_name.starts_with(".xdata$") || addend != 0 {
                        return Err(LinkerError::UnsupportedCoffRelocationTarget);
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
                        return Err(LinkerError::UnsupportedCoffSection);
                    }
                    unwind_info = Some(bytes);
                    unwind_section = Some(
                        u16::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?,
                    );
                    unwind_section_name = Some(target_name);
                }
            }
            if text_sections[0] != text_sections[1]
                || text_section_names[0] != text_section_names[1]
            {
                return Err(LinkerError::InvalidCoffAssociation);
            }
            for (companion, companion_name) in [
                (Some(pdata_section), Some(pdata_name)),
                (unwind_section, unwind_section_name),
            ]
            .into_iter()
            .filter_map(|(section, name)| Some((section?, name?)))
            {
                if let Some(metadata) = comdat_sections.section(companion) {
                    let explicit = metadata.selection == CoffTextComdatSelection::Associative
                        && comdat_sections.root_section(companion) == Some(text_sections[0]);
                    let implicit = metadata.selection != CoffTextComdatSelection::Associative
                        && coff_mingw_companion_matches(companion_name, text_section_names[0]);
                    if !explicit && !implicit {
                        return Err(LinkerError::InvalidCoffAssociation);
                    }
                }
            }
            record_storage[record_count] = PeRuntimeFunction {
                begin_symbol: text_targets[0].0,
                begin_identity: object_identity
                    .map(|object| CoffSectionIdentity::new(object, text_sections[0]))
                    .transpose()?,
                begin_offset: text_targets[0].1,
                end_symbol: text_targets[1].0,
                end_identity: object_identity
                    .map(|object| CoffSectionIdentity::new(object, text_sections[1]))
                    .transpose()?,
                end_offset: text_targets[1].1,
                unwind_info: unwind_info.ok_or(LinkerError::UnsupportedCoffSection)?,
            };
            record_count += 1;
        }
    }
    Ok(&record_storage[..record_count])
}

fn coff_mingw_companion_matches(companion: &str, text: &str) -> bool {
    let companion = companion
        .strip_prefix(".pdata$")
        .or_else(|| companion.strip_prefix(".xdata$"));
    let text = text.strip_prefix(".text$");
    matches!((companion, text), (Some(companion), Some(text)) if !text.is_empty() && companion == text)
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
            if found.is_none() {
                found = Some(symbol);
            }
        }
        index = index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if let Some(symbol) = found {
        return Ok(symbol);
    }
    let section_index =
        usize::try_from(section).map_err(|_| LinkerError::UnsupportedCoffSymbol)?;
    if section_index == 0 {
        return Err(LinkerError::UnsupportedCoffSymbol);
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

fn validate_discardable_coff_debug_section(
    object: &[u8],
    header: usize,
    section_size: usize,
    symbol_count: usize,
) -> Result<(), LinkerError> {
    let characteristics = read_u32(object, header + 36)?;
    if characteristics & 0x0200_0000 == 0
        || characteristics & 0xa100_0000 != 0
        || characteristics & 0x0000_0040 == 0
    {
        return Err(LinkerError::UnsupportedCoff);
    }
    let relocation_count = usize::from(read_u16(object, header + 32)?);
    let relocation_start =
        usize::try_from(read_u32(object, header + 24)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let relocation_end = relocation_start
        .checked_add(
            relocation_count
                .checked_mul(10)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    object
        .get(relocation_start..relocation_end)
        .ok_or(LinkerError::InvalidCoff)?;
    for index in 0..relocation_count {
        let record = relocation_start
            .checked_add(index.checked_mul(10).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let field =
            usize::try_from(read_u32(object, record)?).map_err(|_| LinkerError::OffsetOverflow)?;
        let relocation_width = match read_u16(object, record + 8)? {
            0 | 15 => 0,
            1 => 8,
            2..=9 | 11 | 13 | 14 | 16 => 4,
            10 => 2,
            12 => 1,
            _ => return Err(LinkerError::UnsupportedCoff),
        };
        if field >= section_size
            || field
                .checked_add(relocation_width)
                .filter(|end| *end <= section_size)
                .is_none()
        {
            return Err(LinkerError::InvalidRelocationOffset);
        }
        let target = usize::try_from(read_u32(object, record + 4)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if target >= symbol_count {
            return Err(LinkerError::InvalidCoff);
        }
    }
    Ok(())
}

fn validate_discardable_coff_exclude_directives(
    object: &[u8],
    header: usize,
    contents: &[u8],
    _symbol_count: usize,
) -> Result<(), LinkerError> {
    let characteristics = read_u32(object, header + 36)?;
    if characteristics & 0x0000_0a00 != 0x0000_0a00
        || characteristics & !0x00f0_0a00 != 0
        || read_u16(object, header + 32)? != 0
    {
        return Err(LinkerError::UnsupportedCoffSection);
    }
    if contents.is_empty() || contents.len() > 4096 {
        return Err(LinkerError::UnsupportedCoffSection);
    }
    let prefix = b"-exclude-symbols:";
    let mut directives = 0usize;
    for directive in contents.split(|byte| byte.is_ascii_whitespace()) {
        if directive.is_empty() {
            continue;
        }
        let symbol = directive
            .strip_prefix(prefix)
            .ok_or(LinkerError::UnsupportedCoffSection)?;
        if symbol.is_empty()
            || !symbol.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(*byte, b'_' | b'$' | b'@' | b'?' | b'.')
            })
        {
            return Err(LinkerError::UnsupportedCoffSection);
        }
        directives = directives
            .checked_add(1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if directives == 0 {
        return Err(LinkerError::UnsupportedCoffSection);
    }
    Ok(())
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
    let inventory = inventory_x86_64_coff_comdat_sections(object)?;
    decode_x86_64_coff_text_fragment_from_inventory(
        object,
        fragment_index,
        &inventory,
        relocation_storage,
        definition_storage,
    )
}

pub fn decode_x86_64_coff_text_fragment_from_inventory<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
    decode_x86_64_coff_text_fragment_for_object_from_inventory(
        object,
        fragment_index,
        inventory,
        None,
        relocation_storage,
        definition_storage,
    )
}

/// Decodes one COFF text fragment while projecting every COMDAT read-only
/// section as a distinct object-local section identity.
pub fn decode_x86_64_coff_text_fragment_with_section_identities_from_inventory<
    'data,
    'relocations,
    'definitions,
>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    object_identity: u16,
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
    let identity = CoffSectionIdentity::new(object_identity, 1)?;
    decode_x86_64_coff_text_fragment_for_object_from_inventory(
        object,
        fragment_index,
        inventory,
        Some(identity.object),
        relocation_storage,
        definition_storage,
    )
}

fn decode_x86_64_coff_text_fragment_for_object_from_inventory<'data, 'relocations, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    object_identity: Option<u16>,
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<LinkInput<'data, 'relocations, 'definitions>, LinkerError> {
    inventory.validate_object(object)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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
    let mut readonly_sections = CoffSectionSet::empty();
    let mut discarded_readonly_sections = CoffSectionSet::empty();
    let mut ignored_empty_sections = CoffSectionSet::empty();
    let mut other_text_sections = CoffSectionSet::empty();
    let mut unwind_sections = CoffSectionSet::empty();
    let mut writable_sections = CoffSectionSet::empty();
    let mut tls_sections = CoffSectionSet::empty();
    let mut metadata_sections = CoffSectionSet::empty();
    let mut debug_sections = CoffSectionSet::empty();
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
        let contents = if name == ".bss" || name.starts_with(".bss$") {
            &object[0..0]
        } else {
            object
                .get(
                    offset
                        ..offset
                            .checked_add(size)
                            .ok_or(LinkerError::OffsetOverflow)?,
                )
                .ok_or(LinkerError::InvalidCoff)?
        };
        let section_number = i16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        if name == ".text" || name.starts_with(".text$") {
            if contents.is_empty() {
                ignored_empty_sections.insert(section + 1)?;
                continue;
            }
            other_text_sections.insert(section + 1)?;
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
                ignored_empty_sections.insert(section + 1)?;
                continue;
            }
            readonly_sections.insert(section + 1)?;
        } else if name.starts_with(".xdata$") || name.starts_with(".pdata$") {
            unwind_sections.insert(section + 1)?;
        } else if name.starts_with(".tls$") {
            tls_sections.insert(section + 1)?;
        } else if (name.starts_with(".data$") || name.starts_with(".bss$")) && size != 0 {
            writable_sections.insert(section + 1)?;
        } else if name == ".llvmbc" || name == ".llvmcmd" {
            let characteristics = read_u32(object, header + 36)?;
            let relocation_count = read_u16(object, header + 32)?;
            if characteristics & 0x0000_0800 == 0 || relocation_count != 0 {
                return Err(LinkerError::UnsupportedCoffSection);
            }
            metadata_sections.insert(section + 1)?;
        } else if name == ".drectve" {
            validate_discardable_coff_exclude_directives(
                object,
                header,
                contents,
                symbol_count,
            )?;
            metadata_sections.insert(section + 1)?;
        } else if name == ".debug" || name.starts_with(".debug$") || name.starts_with(".debug_") {
            validate_discardable_coff_debug_section(object, header, contents.len(), symbol_count)?;
            debug_sections.insert(section + 1)?;
        } else if (name == ".data" || name == ".bss") && contents.is_empty() {
            ignored_empty_sections.insert(section + 1)?;
        } else {
            return Err(LinkerError::UnsupportedCoffSection);
        }
    }
    let text = text.ok_or(LinkerError::InvalidCoff)?;
    let text_section = text_section.ok_or(LinkerError::InvalidCoff)?;
    let text_section_u16 = u16::try_from(text_section).map_err(|_| LinkerError::OffsetOverflow)?;

    let mut readonly_span = None;
    for section in 0..section_count {
        if !readonly_sections.contains(section + 1) {
            continue;
        }
        let section_number = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        if inventory.section(section_number).is_some_and(|metadata| {
            object_identity.is_some()
                || metadata.selection != CoffTextComdatSelection::Associative
                || inventory.root_section(section_number) != Some(text_section_u16)
        }) {
            readonly_sections.remove(section + 1)?;
            discarded_readonly_sections.insert(section + 1)?;
            continue;
        }
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let offset = usize::try_from(read_u32(object, header + 20)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        readonly_span = Some(match readonly_span {
            None => (offset, offset + size),
            Some((start, end)) if end <= offset => (start, offset + size),
            Some(_) => return Err(LinkerError::UnsupportedCoffReadonlyLayout),
        });
    }
    if let Some((start, end)) = readonly_span {
        for section in 0..section_count {
            if !discarded_readonly_sections.contains(section + 1) {
                continue;
            }
            let header = 20usize + section * 40;
            let size = usize::try_from(read_u32(object, header + 16)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let offset = usize::try_from(read_u32(object, header + 20)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let discarded_end = offset
                .checked_add(size)
                .ok_or(LinkerError::OffsetOverflow)?;
            if offset < end && discarded_end > start {
                return Err(LinkerError::UnsupportedCoffReadonlyLayout);
            }
        }
        readonly_data = object.get(start..end).ok_or(LinkerError::InvalidCoff)?;
    }

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
                    target: LinkDefinitionTarget::Text(text_offset),
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
                .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
        {
        } else if section > 0
            && (other_text_sections
                .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                || unwind_sections
                    .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                || writable_sections
                    .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                || tls_sections
                    .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                || metadata_sections
                    .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
                || debug_sections
                    .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?))
        {
        } else if section > 0
            && readonly_sections
                .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
        {
        } else if section > 0
            && discarded_readonly_sections
                .contains(usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?)
        {
        } else if section != 0 {
            return Err(LinkerError::UnsupportedCoffSymbol);
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let symbol = defined_symbol
        .or(text_section_name)
        .ok_or(LinkerError::InvalidCoff)?;
    let local_identity = object_identity
        .map(|object_identity| CoffSectionIdentity::new(object_identity, text_section_u16))
        .transpose()?;
    if defined_symbol.is_some()
        && let Some(identity) = local_identity
    {
        if definition_count == definition_storage.len() {
            return Err(LinkerError::TooManyDefinitions);
        }
        definition_storage[definition_count] = LinkDefinition {
            symbol: text_section_name.ok_or(LinkerError::InvalidCoff)?,
            target: LinkDefinitionTarget::CoffTextSection {
                identity,
                offset: 0,
            },
        };
        definition_count += 1;
    }
    let symbol_target = match (defined_symbol, local_identity) {
        (None, Some(identity)) => LinkDefinitionTarget::CoffTextSection {
            identity,
            offset: 0,
        },
        _ => LinkDefinitionTarget::Text(0),
    };

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
        if target_index >= symbol_count {
            return Err(LinkerError::UnsupportedCoffRelocation);
        }
        let relocation_type = read_u16(object, offset + 8)?;
        let target_offset = symbol_offset
            .checked_add(
                target_index
                    .checked_mul(18)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        let target_section = read_i16(object, target_offset + 12)?;
        let target_is_tls = target_section > 0
            && tls_sections
                .contains(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?);
        // IMAGE_REL_AMD64_REL32 is the ordinary code relocation. Rust's
        // Windows TLS access sequence additionally uses IMAGE_REL_AMD64_SECREL
        // for the offset within the selected TLS template; retain that target
        // as typed PE TLS work rather than treating it as an unknown encoding.
        if relocation_type != 4 && !(relocation_type == 11 && target_is_tls) {
            return Err(LinkerError::UnsupportedCoffRelocation);
        }
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
                .contains(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
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
                let section = u16::try_from(target_section)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let target_header = 20 + (usize::from(section) - 1) * 40;
                if let Some(object_identity) = object_identity {
                    let section_size = usize::try_from(read_u32(object, target_header + 16)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?;
                    let offset = usize::try_from(read_u32(object, target_offset + 8)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?;
                    if offset > section_size {
                        return Err(LinkerError::InvalidRelocationOffset);
                    }
                    LinkRelocationTarget::CoffSection {
                        identity: CoffSectionIdentity::new(object_identity, section)?,
                        offset,
                    }
                } else {
                    LinkRelocationTarget::LocalSymbol(coff_section_name(
                        object
                            .get(target_header..target_header + 8)
                            .ok_or(LinkerError::InvalidCoff)?,
                        object,
                        symbols_end,
                        string_size,
                    )?)
                }
            } else {
                return Err(LinkerError::UnsupportedCoffRelocationTarget);
            };
            (target, i64::from(field_addend) - 4)
        } else if target_section > 0
            && readonly_sections
                .contains(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
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
        } else if target_section > 0
            && discarded_readonly_sections
                .contains(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
            && inventory
                .section(u16::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
                .is_some()
        {
            if let Some(object_identity) = object_identity {
                let section =
                    u16::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?;
                let target_header = 20usize
                    .checked_add(
                        usize::from(section - 1)
                            .checked_mul(40)
                            .ok_or(LinkerError::OffsetOverflow)?,
                    )
                    .ok_or(LinkerError::OffsetOverflow)?;
                let section_size = usize::try_from(read_u32(object, target_header + 16)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let symbol_value = usize::try_from(read_u32(object, target_offset + 8)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?;
                let field_addend = usize::try_from(field_addend)
                    .map_err(|_| LinkerError::InvalidRelocationOffset)?;
                let target_offset = symbol_value
                    .checked_add(field_addend)
                    .filter(|offset| *offset <= section_size)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                (
                    LinkRelocationTarget::CoffSection {
                        identity: CoffSectionIdentity::new(object_identity, section)?,
                        offset: target_offset,
                    },
                    -4,
                )
            } else {
                let storage_class = *object
                    .get(target_offset + 16)
                    .ok_or(LinkerError::InvalidCoff)?;
                if storage_class != 2 && storage_class != 3 {
                    return Err(LinkerError::UnsupportedCoffRelocationTarget);
                }
                let name = coff_symbol_name(object, target_offset, symbols_end, string_size)?;
                let target = if storage_class == 2 {
                    LinkRelocationTarget::Symbol(name)
                } else {
                    LinkRelocationTarget::LocalSymbol(name)
                };
                (target, i64::from(field_addend) - 4)
            }
        } else if target_section > 0
            && writable_sections
                .contains(usize::try_from(target_section).map_err(|_| LinkerError::OffsetOverflow)?)
        {
            let storage_class = *object
                .get(target_offset + 16)
                .ok_or(LinkerError::InvalidCoff)?;
            if (storage_class != 2 && storage_class != 3)
                || read_u32(object, target_offset + 8)? != 0
            {
                return Err(LinkerError::UnsupportedCoffRelocationTarget);
            }
            (
                LinkRelocationTarget::PeWritableSymbol(coff_symbol_name(
                    object,
                    target_offset,
                    symbols_end,
                    string_size,
                )?),
                i64::from(field_addend) - 4,
            )
        } else if target_is_tls {
            let section = u16::try_from(target_section)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let target_header = 20 + (usize::from(section) - 1) * 40;
            let size = usize::try_from(read_u32(object, target_header + 16)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let offset = usize::try_from(read_u32(object, target_offset + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if offset > size {
                return Err(LinkerError::InvalidRelocationOffset);
            }
            (
                LinkRelocationTarget::PeTlsSection {
                    identity: CoffSectionIdentity::new(
                        object_identity.ok_or(LinkerError::UnsupportedCoffTls)?,
                        section,
                    )?,
                    offset,
                },
                if relocation_type == 11 {
                    i64::from(field_addend)
                } else {
                    i64::from(field_addend) - 4
                },
            )
        } else {
            return Err(LinkerError::UnsupportedCoffRelocationTarget);
        };
        relocation_storage[index] = LinkRelocation {
            offset: field_offset,
            target,
            addend,
        };
    }

    Ok(LinkInput {
        symbol,
        symbol_target,
        additional_definitions: &definition_storage[..definition_count],
        text,
        readonly_data,
        relocations: &relocation_storage[..relocation_table.1],
    })
}

pub fn x86_64_coff_standalone_readonly_fragment_count(
    object: &[u8],
    inventory: &CoffComdatSections<'_>,
) -> Result<usize, LinkerError> {
    x86_64_coff_projected_readonly_fragment_count(object, inventory, false)
}

pub fn x86_64_coff_section_identity_readonly_fragment_count(
    object: &[u8],
    inventory: &CoffComdatSections<'_>,
) -> Result<usize, LinkerError> {
    x86_64_coff_projected_readonly_fragment_count(object, inventory, true)
}

fn x86_64_coff_projected_readonly_fragment_count(
    object: &[u8],
    inventory: &CoffComdatSections<'_>,
    include_associative: bool,
) -> Result<usize, LinkerError> {
    inventory.validate_object(object)?;
    let section_count = usize::from(read_u16(object, 2)?);
    let symbol_offset =
        usize::try_from(read_u32(object, 8)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbol_count =
        usize::try_from(read_u32(object, 12)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let strings_offset = symbol_offset
        .checked_add(
            symbol_count
                .checked_mul(18)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    let string_size = usize::try_from(read_u32(object, strings_offset)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let mut count = 0usize;
    for section in 0..section_count {
        let header = 20usize + section * 40;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            strings_offset,
            string_size,
        )?;
        let section_number = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        if (name == ".rdata" || name.starts_with(".rdata$"))
            && read_u32(object, header + 16)? != 0
            && inventory.section(section_number).is_some_and(|metadata| {
                include_associative || metadata.selection != CoffTextComdatSelection::Associative
            })
        {
            count = count.checked_add(1).ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    Ok(count)
}

pub fn decode_x86_64_coff_standalone_readonly_fragment<'data, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<CoffReadonlyLinkInput<'data, 'definitions>, LinkerError> {
    decode_x86_64_coff_projected_readonly_fragment(
        object,
        fragment_index,
        inventory,
        None,
        definition_storage,
    )
}

pub fn decode_x86_64_coff_section_identity_readonly_fragment<'data, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    object_identity: u16,
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<CoffReadonlyLinkInput<'data, 'definitions>, LinkerError> {
    CoffSectionIdentity::new(object_identity, 1)?;
    decode_x86_64_coff_projected_readonly_fragment(
        object,
        fragment_index,
        inventory,
        Some(object_identity),
        definition_storage,
    )
}

fn decode_x86_64_coff_projected_readonly_fragment<'data, 'definitions>(
    object: &'data [u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
    object_identity: Option<u16>,
    definition_storage: &'definitions mut [LinkDefinition<'data>; MAX_LINK_DEFINITIONS],
) -> Result<CoffReadonlyLinkInput<'data, 'definitions>, LinkerError> {
    inventory.validate_object(object)?;
    let section_count = usize::from(read_u16(object, 2)?);
    let symbol_offset =
        usize::try_from(read_u32(object, 8)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbol_count =
        usize::try_from(read_u32(object, 12)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let strings_offset = symbol_offset
        .checked_add(
            symbol_count
                .checked_mul(18)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    let string_size = usize::try_from(read_u32(object, strings_offset)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let mut selected = None;
    let mut ordinal = 0usize;
    for section in 0..section_count {
        let header = 20usize + section * 40;
        let name = coff_section_name(
            object
                .get(header..header + 8)
                .ok_or(LinkerError::InvalidCoff)?,
            object,
            strings_offset,
            string_size,
        )?;
        let section_number = u16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?;
        let Some(metadata) = inventory.section(section_number) else {
            continue;
        };
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if size == 0
            || !(name == ".rdata" || name.starts_with(".rdata$"))
            || (object_identity.is_none()
                && metadata.selection == CoffTextComdatSelection::Associative)
        {
            continue;
        }
        if ordinal == fragment_index {
            let raw = usize::try_from(read_u32(object, header + 20)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            let contents = object
                .get(raw..raw.checked_add(size).ok_or(LinkerError::OffsetOverflow)?)
                .ok_or(LinkerError::InvalidCoff)?;
            selected = Some((
                section_number,
                name,
                contents,
                metadata.selection,
                metadata.associated_section,
            ));
            break;
        }
        ordinal += 1;
    }
    let (selected_section, section_name, contents, selection, associated_section) =
        selected.ok_or(LinkerError::InvalidCoff)?;
    let mut primary = None;
    let mut definition_count = 0usize;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let symbol = symbol_offset + symbol_index * 18;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        let storage_class = *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)?;
        if read_i16(object, symbol + 12)?
            == i16::try_from(selected_section).map_err(|_| LinkerError::OffsetOverflow)?
            && (storage_class == 2
                || (object_identity.is_none() && storage_class == 3 && auxiliary == 0))
        {
            let value = usize::try_from(read_u32(object, symbol + 8)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if value > contents.len() {
                return Err(LinkerError::InvalidCoff);
            }
            let name = coff_symbol_name(object, symbol, strings_offset, string_size)?;
            if primary.is_none() && value == 0 {
                primary = Some(name);
            } else {
                if definition_count == definition_storage.len() {
                    return Err(LinkerError::TooManyDefinitions);
                }
                definition_storage[definition_count] = LinkDefinition {
                    symbol: name,
                    target: LinkDefinitionTarget::ReadonlyData(value),
                };
                definition_count += 1;
            }
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Ok(CoffReadonlyLinkInput {
        input: LinkInput {
            symbol: primary.unwrap_or(section_name),
            symbol_target: match object_identity {
                Some(object_identity) => LinkDefinitionTarget::CoffSection {
                    identity: CoffSectionIdentity::new(object_identity, selected_section)?,
                    offset: 0,
                },
                None => LinkDefinitionTarget::ReadonlyData(0),
            },
            additional_definitions: &definition_storage[..definition_count],
            text: &[],
            readonly_data: contents,
            relocations: &[],
        },
        selection,
        section_number: selected_section,
        associated_section,
    })
}

/// Builds a bounded inventory of COFF COMDAT section definitions and validates
/// that every associative chain terminates at a non-associative COMDAT section.
fn coff_comdat_metadata_for_section(
    object: &[u8],
    section_count: u16,
    requested: u16,
) -> Result<Option<CoffComdatSection>, LinkerError> {
    if requested == 0 || requested > section_count {
        return Ok(None);
    }
    let header = 20usize
        .checked_add(
            usize::from(requested - 1)
                .checked_mul(40)
                .ok_or(LinkerError::OffsetOverflow)?,
        )
        .ok_or(LinkerError::OffsetOverflow)?;
    if read_u32(object, header + 36)? & 0x0000_1000 == 0 {
        return Ok(None);
    }
    let symbol_offset =
        usize::try_from(read_u32(object, 8)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let symbol_count =
        usize::try_from(read_u32(object, 12)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let symbol = symbol_offset
            .checked_add(
                symbol_index
                    .checked_mul(18)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        if read_i16(object, symbol + 12)?
            == i16::try_from(requested).map_err(|_| LinkerError::OffsetOverflow)?
        {
            if *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? != 3
                || auxiliary != 1
                || read_u32(object, symbol + 8)? != 0
                || read_u16(object, symbol + 14)? != 0
            {
                return Err(LinkerError::InvalidCoffAssociation);
            }
            let selection = match *object.get(symbol + 32).ok_or(LinkerError::InvalidCoff)? {
                1 => CoffTextComdatSelection::NoDuplicates,
                2 => CoffTextComdatSelection::Any,
                3 => CoffTextComdatSelection::SameSize,
                4 => CoffTextComdatSelection::ExactMatch,
                5 => CoffTextComdatSelection::Associative,
                6 => CoffTextComdatSelection::Largest,
                _ => return Err(LinkerError::InvalidCoffAssociation),
            };
            let associated_section = if selection == CoffTextComdatSelection::Associative {
                let number = read_u16(object, symbol + 30)?;
                if number == 0 || number > section_count {
                    return Err(LinkerError::InvalidCoffAssociation);
                }
                Some(number)
            } else {
                None
            };
            return Ok(Some(CoffComdatSection {
                section_number: requested,
                selection,
                associated_section,
            }));
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    Err(LinkerError::InvalidCoffAssociation)
}

pub fn inventory_x86_64_coff_comdat_sections(
    object: &[u8],
) -> Result<CoffComdatSections<'_>, LinkerError> {
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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

    let mut is_comdat = CoffSectionSet::empty();
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        object
            .get(header..header + 40)
            .ok_or(LinkerError::InvalidCoff)?;
        if read_u32(object, header + 36)? & 0x0000_1000 != 0 {
            is_comdat.insert(section + 1)?;
        }
    }

    let mut first_symbol_seen = CoffSectionSet::empty();
    let mut symbol_index = 0usize;
    while symbol_index < symbol_count {
        let symbol = symbol_offset + symbol_index * 18;
        let auxiliary = usize::from(*object.get(symbol + 17).ok_or(LinkerError::InvalidCoff)?);
        if symbol_index
            .checked_add(auxiliary)
            .filter(|end| *end < symbol_count)
            .is_none()
        {
            return Err(LinkerError::InvalidCoff);
        }
        let section = read_i16(object, symbol + 12)?;
        if section > 0 {
            let section = usize::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?;
            if section > section_count {
                return Err(LinkerError::InvalidCoff);
            }
            if !first_symbol_seen.contains(section) {
                first_symbol_seen.insert(section)?;
                if is_comdat.contains(section) {
                    if *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? != 3
                        || auxiliary != 1
                        || read_u32(object, symbol + 8)? != 0
                        || read_u16(object, symbol + 14)? != 0
                    {
                        return Err(LinkerError::InvalidCoffAssociation);
                    }
                    let selection =
                        match *object.get(symbol + 32).ok_or(LinkerError::InvalidCoff)? {
                            1 => CoffTextComdatSelection::NoDuplicates,
                            2 => CoffTextComdatSelection::Any,
                            3 => CoffTextComdatSelection::SameSize,
                            4 => CoffTextComdatSelection::ExactMatch,
                            5 => CoffTextComdatSelection::Associative,
                            6 => CoffTextComdatSelection::Largest,
                            _ => return Err(LinkerError::InvalidCoffAssociation),
                        };
                    let associated_section = if selection == CoffTextComdatSelection::Associative {
                        let number = read_u16(object, symbol + 30)?;
                        if number == 0 || usize::from(number) > section_count {
                            return Err(LinkerError::InvalidCoffAssociation);
                        }
                        Some(number)
                    } else {
                        None
                    };
                    let _ = (selection, associated_section);
                } else if *object.get(symbol + 16).ok_or(LinkerError::InvalidCoff)? == 3
                    && auxiliary == 1
                    && *object.get(symbol + 32).ok_or(LinkerError::InvalidCoff)? != 0
                {
                    return Err(LinkerError::InvalidCoffAssociation);
                }
            }
        }
        symbol_index = symbol_index
            .checked_add(auxiliary + 1)
            .ok_or(LinkerError::OffsetOverflow)?;
    }

    let section_count_u16 =
        u16::try_from(section_count).map_err(|_| LinkerError::OffsetOverflow)?;
    let mut comdat_count = 0usize;
    for section in 1..=section_count {
        if !is_comdat.contains(section) {
            continue;
        }
        comdat_count += 1;
        let metadata = coff_comdat_metadata_for_section(
            object,
            section_count_u16,
            u16::try_from(section).map_err(|_| LinkerError::OffsetOverflow)?,
        )?
        .ok_or(LinkerError::InvalidCoffAssociation)?;
        let mut cursor = metadata;
        let mut visited = CoffSectionSet::empty();
        while cursor.selection == CoffTextComdatSelection::Associative {
            let cursor_index = usize::from(cursor.section_number);
            if visited.contains(cursor_index) {
                return Err(LinkerError::InvalidCoffAssociation);
            }
            visited.insert(cursor_index)?;
            let parent = usize::from(
                cursor
                    .associated_section
                    .ok_or(LinkerError::InvalidCoffAssociation)?,
            );
            if !is_comdat.contains(parent) {
                return Err(LinkerError::InvalidCoffAssociation);
            }
            cursor = coff_comdat_metadata_for_section(
                object,
                section_count_u16,
                u16::try_from(parent).map_err(|_| LinkerError::OffsetOverflow)?,
            )?
            .ok_or(LinkerError::InvalidCoffAssociation)?;
        }
    }
    Ok(CoffComdatSections {
        object,
        section_count: section_count_u16,
        len: comdat_count,
    })
}

/// Returns the section-definition duplicate-selection policy for one nonempty
/// COFF text fragment. The fragment order is identical to the text decoder.
pub fn x86_64_coff_text_fragment_comdat_selection(
    object: &[u8],
    fragment_index: usize,
) -> Result<CoffTextComdatSelection, LinkerError> {
    let inventory = inventory_x86_64_coff_comdat_sections(object)?;
    x86_64_coff_text_fragment_comdat_selection_from_inventory(object, fragment_index, &inventory)
}

pub fn x86_64_coff_text_fragment_comdat_selection_from_inventory(
    object: &[u8],
    fragment_index: usize,
    inventory: &CoffComdatSections<'_>,
) -> Result<CoffTextComdatSelection, LinkerError> {
    inventory.validate_object(object)?;
    if read_u16(object, 0)? != 0x8664 || read_u16(object, 16)? != 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    let section_count = usize::from(read_u16(object, 2)?);
    if section_count == 0 {
        return Err(LinkerError::UnsupportedCoff);
    }
    if section_count > MAX_COFF_SECTIONS {
        return Err(LinkerError::TooManyCoffSections);
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

    let mut text_ordinal = 0usize;
    let mut selected_section = None;
    for section in 0..section_count {
        let header = 20usize
            .checked_add(section.checked_mul(40).ok_or(LinkerError::OffsetOverflow)?)
            .ok_or(LinkerError::OffsetOverflow)?;
        let size = usize::try_from(read_u32(object, header + 16)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if size == 0 {
            continue;
        }
        let raw_name = object
            .get(header..header + 8)
            .ok_or(LinkerError::InvalidCoff)?;
        let string_size = usize::try_from(read_u32(object, symbols_end)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if string_size < 4 {
            return Err(LinkerError::InvalidCoff);
        }
        let name = coff_section_name(raw_name, object, symbols_end, string_size)?;
        if name == ".text" || name.starts_with(".text$") {
            if text_ordinal == fragment_index {
                selected_section = Some((
                    i16::try_from(section + 1).map_err(|_| LinkerError::OffsetOverflow)?,
                    read_u32(object, header + 36)? & 0x0000_1000 != 0,
                ));
                break;
            }
            text_ordinal = text_ordinal
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    let (selected_section, is_comdat) = selected_section.ok_or(LinkerError::InvalidCoff)?;
    if !is_comdat {
        return Ok(CoffTextComdatSelection::None);
    }
    let metadata = inventory
        .section(u16::try_from(selected_section).map_err(|_| LinkerError::OffsetOverflow)?)
        .ok_or(LinkerError::UnsupportedCoff)?;
    if metadata.selection == CoffTextComdatSelection::Associative {
        return Err(LinkerError::UnsupportedCoff);
    }
    Ok(metadata.selection)
}

/// Selects the sections reachable from exact defined ELF symbols through RELA
/// edges. This is a format-graph pass only; decoding and layout remain separate.
pub fn select_x86_64_elf_sections(
    object: &[u8],
    root_symbols: &[&str],
) -> Result<ElfSectionSelection, LinkerError> {
    let symbol_table = elf_symbol_table_view(object)?;
    select_x86_64_elf_sections_from_view(object, root_symbols, symbol_table, 0, None, None)
}

fn select_x86_64_elf_sections_from_view(
    object: &[u8],
    root_symbols: &[&str],
    symbol_table: ElfSymbolTableView<'_>,
    object_index: usize,
    prepared_groups: Option<&[ElfComdatGroup<'_>]>,
    prepared_initializers: Option<&[ElfInitializerSection]>,
) -> Result<ElfSectionSelection, LinkerError> {
    if root_symbols.is_empty() {
        return Err(LinkerError::EmptySymbol);
    }
    for root in root_symbols {
        validate_symbol(root)?;
    }
    let section_offset = symbol_table.section_offset;
    let section_count = symbol_table.section_count;
    let symbols_index = symbol_table.symbols_index;
    let symbols = symbol_table.symbols;
    let strings = symbol_table.strings;

    let mut selected = [false; MAX_ELF_SECTIONS];
    for root in root_symbols {
        let mut found = false;
        for symbol_index in 1..symbols.len() / 24 {
            let symbol = symbol_index * 24;
            let name_offset = usize::try_from(read_u32_elf(symbols, symbol)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if name_offset == 0 {
                continue;
            }
            if elf_string(strings, name_offset)? != *root {
                continue;
            }
            let binding = *symbols.get(symbol + 4).ok_or(LinkerError::InvalidElf)? >> 4;
            let section = usize::from(read_u16_elf(symbols, symbol + 6)?);
            if section == 0 || section == 0xfff1 {
                continue;
            }
            if !matches!(binding, 1 | 2) {
                return Err(LinkerError::UndefinedSymbol);
            }
            if section == 0xfff2 {
                validate_elf_common_shape(
                    to_usize_elf(read_u64_elf(symbols, symbol + 16)?)?,
                    to_usize_elf(read_u64_elf(symbols, symbol + 8)?)?,
                )?;
                found = true;
                break;
            }
            if section >= section_count {
                return Err(LinkerError::UndefinedSymbol);
            }
            if elf_section_is_discarded(prepared_groups.unwrap_or(&[]), object_index, section) {
                continue;
            }
            selected[section] = true;
            found = true;
            break;
        }
        if !found {
            return Err(LinkerError::UndefinedSymbol);
        }
    }

    if let Some(initializers) = prepared_initializers {
        for initializer in initializers {
            let section = usize::from(initializer.section_index);
            if !elf_section_is_discarded(prepared_groups.unwrap_or(&[]), object_index, section) {
                selected[section] = true;
            }
        }
    } else {
        for section in 1..section_count {
            let header = elf_section_header(section_offset, section_count, section)?;
            if matches!(read_u32_elf(object, header + 4)?, 14..=16)
                && !elf_section_is_discarded(prepared_groups.unwrap_or(&[]), object_index, section)
            {
                selected[section] = true;
            }
        }
    }

    loop {
        let mut changed = false;
        if let Some(groups) = prepared_groups {
            for group in groups.iter().filter(|group| group.winner) {
                changed |= expand_selected_comdat_members(
                    object,
                    symbol_table,
                    group.members,
                    &mut selected,
                )?;
            }
        } else {
            for group_index in 1..section_count {
                let Some((_signature, members)) =
                    elf_comdat_group_view(object, symbol_table, group_index)?
                else {
                    continue;
                };
                changed |=
                    expand_selected_comdat_members(object, symbol_table, members, &mut selected)?;
            }
        }
        for relocation_index in 1..section_count {
            let relocation_header =
                elf_section_header(section_offset, section_count, relocation_index)?;
            if read_u32_elf(object, relocation_header + 4)? != 4 {
                continue;
            }
            let target = usize::try_from(read_u32_elf(object, relocation_header + 44)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if target >= section_count || !selected[target] {
                continue;
            }
            let linked_symbols = usize::try_from(read_u32_elf(object, relocation_header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?;
            if linked_symbols != symbols_index
                || read_u64_elf(object, relocation_header + 56)? != 24
            {
                return Err(LinkerError::UnsupportedElf);
            }
            let relocations =
                elf_section_contents(object, section_offset, section_count, relocation_index)?;
            if relocations.len() % 24 != 0 {
                return Err(LinkerError::InvalidElf);
            }
            for relocation in (0..relocations.len()).step_by(24) {
                let symbol_index = to_usize_elf(read_u64_elf(relocations, relocation + 8)? >> 32)?;
                let symbol = symbol_index
                    .checked_mul(24)
                    .ok_or(LinkerError::OffsetOverflow)?;
                symbols
                    .get(symbol..symbol + 24)
                    .ok_or(LinkerError::InvalidElf)?;
                let dependency = usize::from(read_u16_elf(symbols, symbol + 6)?);
                if dependency == 0 || dependency == 0xfff1 {
                    continue;
                }
                if dependency >= section_count {
                    return Err(LinkerError::InvalidElf);
                }
                if elf_section_is_discarded(
                    prepared_groups.unwrap_or(&[]),
                    object_index,
                    dependency,
                ) {
                    continue;
                }
                if !selected[dependency] {
                    selected[dependency] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut selection = ElfSectionSelection {
        indices: [0; MAX_LINK_INPUTS],
        length: 0,
        object_address: object.as_ptr() as usize,
        object_length: object.len(),
    };
    for (index, is_selected) in selected[..section_count].iter().enumerate() {
        if !is_selected {
            continue;
        }
        if selection.length == selection.indices.len() {
            return Err(LinkerError::TooManyElfSections);
        }
        selection.indices[selection.length] =
            u16::try_from(index).map_err(|_| LinkerError::TooManyElfSections)?;
        selection.length += 1;
    }
    Ok(selection)
}

fn expand_selected_comdat_members(
    object: &[u8],
    symbol_table: ElfSymbolTableView<'_>,
    members: &[u8],
    selected: &mut [bool; MAX_ELF_SECTIONS],
) -> Result<bool, LinkerError> {
    let mut selected_member = false;
    for member in members.chunks_exact(4) {
        let member_index =
            usize::try_from(read_u32_elf(member, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        selected_member |= selected[member_index];
    }
    if !selected_member {
        return Ok(false);
    }

    let mut changed = false;
    for member in members.chunks_exact(4) {
        let member_index =
            usize::try_from(read_u32_elf(member, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        let member_header = elf_section_header(
            symbol_table.section_offset,
            symbol_table.section_count,
            member_index,
        )?;
        if read_u64_elf(object, member_header + 8)? & 0x2 != 0 && !selected[member_index] {
            selected[member_index] = true;
            changed = true;
        }
    }
    Ok(changed)
}

/// Selects the stable cross-object section graph rooted at an exact entry.
/// Local RELA edges are expanded by the per-object pass; undefined targets are
/// resolved with conventional strong-over-weak static symbol selection.
pub fn select_x86_64_elf_link_sections<'a>(
    objects: &[&'a [u8]],
    entry_symbol: &'a str,
) -> Result<ElfLinkSectionSelections, LinkerError> {
    select_x86_64_elf_link_sections_detailed(objects, entry_symbol).map_err(|error| error.kind)
}

/// Like [`select_x86_64_elf_link_sections`], but retains the exact unresolved
/// symbol in a bounded borrowed diagnostic when static resolution fails.
pub fn select_x86_64_elf_link_sections_detailed<'a>(
    objects: &[&'a [u8]],
    entry_symbol: &'a str,
) -> Result<ElfLinkSectionSelections, ElfLinkSelectionError<'a>> {
    if objects.is_empty() {
        return Err(LinkerError::EmptyInput.into());
    }
    if objects.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs.into());
    }
    validate_symbol(entry_symbol)?;
    let empty = ElfSectionSelection {
        indices: [0; MAX_LINK_INPUTS],
        length: 0,
        object_address: objects[0].as_ptr() as usize,
        object_length: objects[0].len(),
    };
    let mut result = ElfLinkSectionSelections {
        selections: [empty; MAX_LINK_INPUTS],
        length: objects.len(),
    };
    for (index, object) in objects.iter().enumerate() {
        result.selections[index] = ElfSectionSelection {
            indices: [0; MAX_LINK_INPUTS],
            length: 0,
            object_address: object.as_ptr() as usize,
            object_length: object.len(),
        };
    }
    let mut symbol_tables = [None; MAX_LINK_INPUTS];
    for (index, object) in objects.iter().enumerate() {
        symbol_tables[index] = Some(elf_symbol_table_view(object)?);
    }
    let mut comdat_winners = [None; MAX_ELF_COMDAT_GROUPS];
    let mut comdat_winner_count = 0usize;
    let mut comdat_group_count = 0usize;
    let empty_initializer = ElfInitializerSection {
        object_index: 0,
        section_index: 0,
    };
    let mut initializer_sections = [empty_initializer; MAX_LINK_INPUTS];
    let mut initializer_count = 0usize;
    let empty_group = ElfComdatGroup {
        object_index: 0,
        members: &[],
        winner: false,
    };
    let mut comdat_groups = [empty_group; MAX_ELF_COMDAT_GROUPS];
    for (object_index, object) in objects.iter().enumerate() {
        let symbol_table = symbol_tables[object_index].ok_or(LinkerError::InvalidElf)?;
        for group_index in 1..symbol_table.section_count {
            let header = elf_section_header(
                symbol_table.section_offset,
                symbol_table.section_count,
                group_index,
            )?;
            let section_type = read_u32_elf(object, header + 4)?;
            if matches!(section_type, 14..=16) {
                if initializer_count == initializer_sections.len() {
                    return Err(LinkerError::TooManyElfSections.into());
                }
                initializer_sections[initializer_count] = ElfInitializerSection {
                    object_index: u16::try_from(object_index)
                        .map_err(|_| LinkerError::TooManyInputs)?,
                    section_index: u16::try_from(group_index)
                        .map_err(|_| LinkerError::TooManyElfSections)?,
                };
                initializer_count += 1;
            }
            if section_type != 17 {
                continue;
            }
            let Some((signature, members)) =
                elf_comdat_group_view(object, symbol_table, group_index)?
            else {
                return Err(LinkerError::InvalidElf.into());
            };
            if comdat_group_count == MAX_ELF_COMDAT_GROUPS {
                return Err(LinkerError::TooManyElfComdatGroups.into());
            }
            comdat_group_count += 1;
            let winner = !comdat_winners[..comdat_winner_count].contains(&Some(signature));
            if winner {
                if comdat_winner_count == comdat_winners.len() {
                    return Err(LinkerError::TooManyElfComdatGroups.into());
                }
                comdat_winners[comdat_winner_count] = Some(signature);
                comdat_winner_count += 1;
            }
            comdat_groups[comdat_group_count - 1] = ElfComdatGroup {
                object_index: u16::try_from(object_index)
                    .map_err(|_| LinkerError::TooManyInputs)?,
                members,
                winner,
            };
        }
    }
    let mut unresolved = [None; MAX_ARCHIVE_SYMBOLS];
    unresolved[0] = Some(entry_symbol);
    let mut unresolved_length = 1usize;
    let mut cursor = 0usize;
    while cursor < unresolved_length {
        let symbol = unresolved[cursor].ok_or(LinkerError::InvalidElf)?;
        cursor += 1;
        let Some(object_index) = resolve_elf_object_definition(
            &symbol_tables[..objects.len()],
            &comdat_groups[..comdat_group_count],
            symbol,
        )?
        else {
            return Err(ElfLinkSelectionError {
                kind: LinkerError::UndefinedSymbol,
                symbol: Some(symbol),
            });
        };
        let symbol_table = symbol_tables[object_index].ok_or(LinkerError::InvalidElf)?;
        let object_index_u16 =
            u16::try_from(object_index).map_err(|_| LinkerError::TooManyInputs)?;
        let group_start = comdat_groups[..comdat_group_count]
            .partition_point(|group| group.object_index < object_index_u16);
        let group_end = comdat_groups[..comdat_group_count]
            .partition_point(|group| group.object_index <= object_index_u16);
        let initializer_start = initializer_sections[..initializer_count]
            .partition_point(|section| section.object_index < object_index_u16);
        let initializer_end = initializer_sections[..initializer_count]
            .partition_point(|section| section.object_index <= object_index_u16);
        let addition = select_x86_64_elf_sections_from_view(
            objects[object_index],
            &[symbol],
            symbol_table,
            object_index,
            Some(&comdat_groups[group_start..group_end]),
            Some(&initializer_sections[initializer_start..initializer_end]),
        )?;
        let destination = &mut result.selections[object_index];
        for &section in addition.indices() {
            if destination.indices().contains(&section) {
                continue;
            }
            if destination.length == destination.indices.len() {
                return Err(LinkerError::TooManyElfSections.into());
            }
            destination.indices[destination.length] = section;
            destination.length += 1;
        }
        destination.indices[..destination.length].sort_unstable();
        let relocations =
            decode_x86_64_elf_selected_relocations(objects[object_index], destination)?;
        for relocation in relocations.relocations() {
            let ElfSelectedRelocationTarget::Symbol(target) = relocation.target else {
                continue;
            };
            if is_elf_array_boundary_symbol(target)
                && resolve_elf_object_definition(
                    &symbol_tables[..objects.len()],
                    &comdat_groups[..comdat_group_count],
                    target,
                )?
                .is_none()
            {
                continue;
            }
            if unresolved[..unresolved_length]
                .iter()
                .any(|queued| *queued == Some(target))
            {
                continue;
            }
            if unresolved_length == unresolved.len() {
                return Err(LinkerError::TooManyArchiveSymbols.into());
            }
            unresolved[unresolved_length] = Some(target);
            unresolved_length += 1;
        }
    }
    Ok(result)
}

#[derive(Clone, Copy)]
struct ElfSymbolTableView<'a> {
    section_offset: usize,
    section_count: usize,
    symbols_index: usize,
    symbols: &'a [u8],
    strings: &'a [u8],
}

#[derive(Clone, Copy)]
struct ElfComdatGroup<'a> {
    object_index: u16,
    members: &'a [u8],
    winner: bool,
}

#[derive(Clone, Copy)]
struct ElfInitializerSection {
    object_index: u16,
    section_index: u16,
}

fn elf_section_is_discarded(
    groups: &[ElfComdatGroup<'_>],
    object_index: usize,
    section_index: usize,
) -> bool {
    let Ok(object_index) = u16::try_from(object_index) else {
        return false;
    };
    groups.iter().any(|group| {
        !group.winner
            && group.object_index == object_index
            && group.members.chunks_exact(4).any(|member| {
                <[u8; 4]>::try_from(member)
                    .ok()
                    .map(u32::from_le_bytes)
                    .and_then(|member| usize::try_from(member).ok())
                    == Some(section_index)
            })
    })
}

fn elf_comdat_group_view<'a>(
    object: &'a [u8],
    symbol_table: ElfSymbolTableView<'a>,
    group_index: usize,
) -> Result<Option<(&'a str, &'a [u8])>, LinkerError> {
    let group_header = elf_section_header(
        symbol_table.section_offset,
        symbol_table.section_count,
        group_index,
    )?;
    if read_u32_elf(object, group_header + 4)? != 17 {
        return Ok(None);
    }
    if usize::try_from(read_u32_elf(object, group_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?
        != symbol_table.symbols_index
        || read_u64_elf(object, group_header + 56)? != 4
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let signature_index = usize::try_from(read_u32_elf(object, group_header + 44)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let signature_offset = signature_index
        .checked_mul(24)
        .ok_or(LinkerError::OffsetOverflow)?;
    let signature = symbol_table
        .symbols
        .get(signature_offset..signature_offset + 24)
        .ok_or(LinkerError::InvalidElf)?;
    let signature_name =
        usize::try_from(read_u32_elf(signature, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
    let signature_binding = *signature.get(4).ok_or(LinkerError::InvalidElf)? >> 4;
    if signature_name == 0 || !matches!(signature_binding, 1 | 2) {
        return Err(LinkerError::UnsupportedElf);
    }
    let signature_name = elf_string(symbol_table.strings, signature_name)?;
    validate_symbol(signature_name)?;
    let group = elf_section_contents(
        object,
        symbol_table.section_offset,
        symbol_table.section_count,
        group_index,
    )?;
    if group.len() < 8 || group.len() % 4 != 0 || read_u32_elf(group, 0)? != 1 {
        return Err(LinkerError::UnsupportedElf);
    }
    let members = &group[4..];
    for member in members.chunks_exact(4) {
        let member_index =
            usize::try_from(read_u32_elf(member, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        if member_index == 0 || member_index >= symbol_table.section_count {
            return Err(LinkerError::InvalidElf);
        }
        let member_header = elf_section_header(
            symbol_table.section_offset,
            symbol_table.section_count,
            member_index,
        )?;
        if read_u64_elf(object, member_header + 8)? & 0x200 == 0 {
            return Err(LinkerError::InvalidElf);
        }
    }
    Ok(Some((signature_name, members)))
}

fn resolve_elf_object_definition(
    symbol_tables: &[Option<ElfSymbolTableView<'_>>],
    discarded: &[ElfComdatGroup<'_>],
    symbol: &str,
) -> Result<Option<usize>, LinkerError> {
    let mut weak = None;
    let mut common = None;
    let mut strong = None;
    for (object_index, symbol_table) in symbol_tables.iter().enumerate() {
        let Some(symbol_table) = symbol_table else {
            return Err(LinkerError::InvalidElf);
        };
        let Some((binding, is_common)) =
            elf_object_definition_binding(*symbol_table, discarded, object_index, symbol)?
        else {
            continue;
        };
        if is_common {
            if common.is_none() {
                common = Some(object_index);
            }
            continue;
        }
        match binding {
            ElfSelectedSymbolBinding::Global if strong.replace(object_index).is_some() => {
                return Err(LinkerError::DuplicateSymbol);
            }
            ElfSelectedSymbolBinding::Global => {}
            ElfSelectedSymbolBinding::Weak if weak.is_none() => weak = Some(object_index),
            ElfSelectedSymbolBinding::Weak => {}
        }
    }
    Ok(strong.or(common).or(weak))
}

fn elf_object_definition_binding(
    symbol_table: ElfSymbolTableView<'_>,
    discarded: &[ElfComdatGroup<'_>],
    object_index: usize,
    symbol_name: &str,
) -> Result<Option<(ElfSelectedSymbolBinding, bool)>, LinkerError> {
    let symbols = symbol_table.symbols;
    let strings = symbol_table.strings;
    let section_count = symbol_table.section_count;
    let mut found: Option<(ElfSelectedSymbolBinding, bool)> = None;
    for record in symbols[24..].chunks_exact(24) {
        let name_offset =
            usize::try_from(read_u32_elf(record, 0)?).map_err(|_| LinkerError::OffsetOverflow)?;
        if name_offset == 0 || elf_string(strings, name_offset)? != symbol_name {
            continue;
        }
        let section = usize::from(read_u16_elf(record, 6)?);
        if section == 0 || section == 0xfff1 {
            continue;
        }
        let is_common = section == 0xfff2;
        if !is_common && section >= section_count {
            return Err(LinkerError::InvalidElf);
        }
        if !is_common && elf_section_is_discarded(discarded, object_index, section) {
            continue;
        }
        let binding = match *record.get(4).ok_or(LinkerError::InvalidElf)? >> 4 {
            1 => ElfSelectedSymbolBinding::Global,
            2 => ElfSelectedSymbolBinding::Weak,
            _ => continue,
        };
        if is_common {
            validate_elf_common_shape(
                to_usize_elf(read_u64_elf(record, 16)?)?,
                to_usize_elf(read_u64_elf(record, 8)?)?,
            )?;
        }
        let candidate = (binding, is_common);
        if let Some(existing) = found {
            if existing.1 && is_common {
                continue;
            }
            return Err(LinkerError::DuplicateSymbol);
        }
        found = Some(candidate);
    }
    Ok(found)
}

fn elf_symbol_table_view(object: &[u8]) -> Result<ElfSymbolTableView<'_>, LinkerError> {
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(object.get(7), Some(0 | 3))
        || object.get(8) != Some(&0)
        || read_u16_elf(object, 16)? != 1
        || read_u16_elf(object, 18)? != 62
        || read_u32_elf(object, 20)? != 1
        || read_u16_elf(object, 52)? != 64
        || read_u16_elf(object, 58)? != 64
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let section_names_index = usize::from(read_u16_elf(object, 62)?);
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) || section_names_index >= section_count {
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
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        if read_u32_elf(object, header + 4)? == 2 && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    let strings_index = usize::try_from(read_u32_elf(object, symbols_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    if strings_index >= section_count || read_u64_elf(object, symbols_header + 56)? != 24 {
        return Err(LinkerError::InvalidElf);
    }
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    Ok(ElfSymbolTableView {
        section_offset,
        section_count,
        symbols_index,
        symbols,
        strings,
    })
}

/// Decodes the exact bounded ELF64 relocatable subset emitted by `mrml-rustc`.
pub fn decode_x86_64_elf<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [LinkRelocation<'data>; MAX_LINK_RELOCATIONS],
) -> Result<LinkInput<'data, 'relocations, 'data>, LinkerError> {
    let mut definitions = [LinkDefinition {
        symbol: "unused",
        target: LinkDefinitionTarget::Text(0),
    }; MAX_LINK_DEFINITIONS];
    let decoded = decode_x86_64_elf_with_definitions(object, relocation_storage, &mut definitions)?;
    if !decoded.additional_definitions.is_empty() {
        return Err(LinkerError::UnsupportedElf);
    }
    Ok(LinkInput {
        symbol: decoded.symbol,
        symbol_target: decoded.symbol_target,
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
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(object.get(7), Some(0 | 3))
        || object.get(8) != Some(&0)
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
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) || section_names_index >= section_count {
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

    let mut text_sections = [false; MAX_ELF_SECTIONS];
    let mut text_span = None;
    let mut text_owner = None;
    let mut readonly_sections = [false; MAX_ELF_SECTIONS];
    let mut readonly_span = None;
    let mut writable_sections = [false; MAX_ELF_SECTIONS];
    let mut relocation_sections = [false; MAX_ELF_SECTIONS];
    let mut data_relocation_sections = [false; MAX_ELF_SECTIONS];
    let mut symbols_index = None;
    let mut strings_index = None;
    let mut ignored_sections = [false; MAX_ELF_SECTIONS];
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        let name_offset = usize::try_from(read_u32_elf(object, header)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let name = elf_string(section_names, name_offset)?;
        let section_type = read_u32_elf(object, header + 4)?;
        let contents = if section_type == 8 {
            &object[0..0]
        } else {
            elf_section_contents(object, section_offset, section_count, index)?
        };
        match name {
            name if (name == ".text" || name.starts_with(".text.")) && contents.is_empty() => {
                ignored_sections[index] = true;
            }
            name if name == ".text" || name.starts_with(".text.") => {
                let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
                let end = start
                    .checked_add(contents.len())
                    .ok_or(LinkerError::OffsetOverflow)?;
                text_sections[index] = true;
                if text_owner.is_none() {
                    text_owner = Some(name);
                }
                text_span = Some(match text_span {
                    None => (start, end),
                    Some((first, previous_end))
                        if previous_end <= start
                            && object
                                .get(previous_end..start)
                                .map(|gap| gap.iter().all(|byte| *byte == 0))
                                .unwrap_or(false) =>
                    {
                        (first, end)
                    }
                    Some(_) => return Err(LinkerError::UnsupportedElf),
                });
            }
            name if (name == ".rodata" || name.starts_with(".rodata.")) && contents.is_empty() => {
                if section_type != 1
                    || read_u64_elf(object, header + 8)? & 2 == 0
                    || !matches!(read_u64_elf(object, header + 48)?, 1..=16)
                    || !read_u64_elf(object, header + 48)?.is_power_of_two()
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                readonly_sections[index] = true;
                ignored_sections[index] = true;
            }
            name if name == ".rodata" || name.starts_with(".rodata.") => {
                let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
                let end = start
                    .checked_add(contents.len())
                    .ok_or(LinkerError::OffsetOverflow)?;
                readonly_sections[index] = true;
                readonly_span = Some(match readonly_span {
                    None => (start, end),
                    Some((first, previous_end))
                        if previous_end <= start
                            && object
                                .get(previous_end..start)
                                .map(|gap| gap.iter().all(|byte| *byte == 0))
                                .unwrap_or(false) =>
                    {
                        (first, end)
                    }
                    Some(_) => return Err(LinkerError::UnsupportedElf),
                });
            }
            name if name == ".data" || name.starts_with(".data.") => {
                if section_type != 1 || read_u64_elf(object, header + 8)? != 3 {
                    return Err(LinkerError::UnsupportedElf);
                }
                writable_sections[index] = true;
            }
            name if name == ".bss" || name.starts_with(".bss.") => {
                if section_type != 8 || read_u64_elf(object, header + 8)? != 3 {
                    return Err(LinkerError::UnsupportedElf);
                }
                writable_sections[index] = true;
            }
            name if name == ".rela.text" || name.starts_with(".rela.text.") => {
                relocation_sections[index] = true;
            }
            name if name == ".rela.data" || name.starts_with(".rela.data.") => {
                if read_u32_elf(object, header + 4)? != 4
                    || read_u64_elf(object, header + 8)? & 0x40 == 0
                    || read_u64_elf(object, header + 56)? != 24
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                data_relocation_sections[index] = true;
                ignored_sections[index] = true;
            }
            ".eh_frame" => {
                if read_u32_elf(object, header + 4)? != 0x7000_0001
                    || read_u64_elf(object, header + 8)? != 2
                    || read_u64_elf(object, header + 48)? != 8
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ignored_sections[index] = true;
            }
            ".rela.eh_frame" => {
                if read_u32_elf(object, header + 4)? != 4
                    || read_u64_elf(object, header + 8)? != 0x40
                    || read_u64_elf(object, header + 48)? != 8
                    || read_u64_elf(object, header + 56)? != 24
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ignored_sections[index] = true;
            }
            ".symtab" if symbols_index.replace(index).is_none() => {}
            ".strtab" if strings_index.replace(index).is_none() => {}
            ".shstrtab" if index == section_names_index => {}
            ".comment" => {
                if read_u32_elf(object, header + 4)? != 1
                    || read_u64_elf(object, header + 8)? & 2 != 0
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ignored_sections[index] = true;
            }
            ".note.GNU-stack" => {
                if read_u32_elf(object, header + 4)? != 1
                    || read_u64_elf(object, header + 8)? != 0
                    || !contents.is_empty()
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ignored_sections[index] = true;
            }
            ".llvmbc" | ".llvmcmd" => {
                if read_u32_elf(object, header + 4)? != 1
                    || read_u64_elf(object, header + 8)? & 0x8000_0000 == 0
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ignored_sections[index] = true;
            }
            _ => return Err(LinkerError::UnsupportedElf),
        }
    }
    let (text_start, text_end) = text_span.unwrap_or((0, 0));
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let strings_index = strings_index.ok_or(LinkerError::InvalidElf)?;
    let text = object
        .get(text_start..text_end)
        .ok_or(LinkerError::InvalidElf)?;
    let readonly_data = match readonly_span {
        Some((start, end)) => object.get(start..end).ok_or(LinkerError::InvalidElf)?,
        None => &object[0..0],
    };
    let readonly_start = readonly_span.map(|(start, _)| start);
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
        if text_sections.get(section).copied().unwrap_or(false) && binding == 1 {
            let text_offset = elf_combined_text_offset(
                object,
                section_offset,
                section_count,
                section,
                text_start,
                read_u64_elf(symbols, offset + 8)?,
            )?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidElf);
            }
            let name = elf_string(
                strings,
                usize::try_from(read_u32_elf(symbols, offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
            let target = LinkDefinitionTarget::Text(text_offset);
            if defined_symbol.is_none() {
                defined_symbol = Some((name, target));
            } else {
                if definition_count == definition_storage.len() {
                    return Err(LinkerError::TooManyDefinitions);
                }
                definition_storage[definition_count] = LinkDefinition {
                    symbol: name,
                    target,
                };
                definition_count += 1;
            }
        } else if readonly_sections.get(section).copied().unwrap_or(false) && binding == 1 {
            let readonly_offset = elf_readonly_offset(
                object,
                section_offset,
                section_count,
                section,
                readonly_start,
                read_u64_elf(symbols, offset + 8)?,
            )?;
            if readonly_offset > readonly_data.len() {
                return Err(LinkerError::InvalidElf);
            }
            let name = elf_string(
                strings,
                usize::try_from(read_u32_elf(symbols, offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
            let target = LinkDefinitionTarget::ReadonlyData(readonly_offset);
            if defined_symbol.is_none() {
                defined_symbol = Some((name, target));
            } else {
                if definition_count == definition_storage.len() {
                    return Err(LinkerError::TooManyDefinitions);
                }
                definition_storage[definition_count] = LinkDefinition {
                    symbol: name,
                    target,
                };
                definition_count += 1;
            }
        } else if text_sections.get(section).copied().unwrap_or(false) && binding == 0 {
            let text_offset = elf_combined_text_offset(
                object,
                section_offset,
                section_count,
                section,
                text_start,
                read_u64_elf(symbols, offset + 8)?,
            )?;
            if text_offset > text.len() {
                return Err(LinkerError::InvalidElf);
            }
        } else if binding == 0 && section >= 0xff00 {
        } else if section != 0
            && !readonly_sections.get(section).copied().unwrap_or(false)
            && !writable_sections.get(section).copied().unwrap_or(false)
            && !text_sections.get(section).copied().unwrap_or(false)
            && !relocation_sections.get(section).copied().unwrap_or(false)
            && !ignored_sections.get(section).copied().unwrap_or(false)
        {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let (symbol, symbol_target) = defined_symbol
        .or_else(|| text_owner.map(|symbol| (symbol, LinkDefinitionTarget::Text(0))))
        .ok_or(LinkerError::InvalidElf)?;

    let mut relocation_count = 0usize;
    for index in 1..section_count {
        if !relocation_sections[index] {
            continue;
        }
        let header = elf_section_header(section_offset, section_count, index)?;
        let relocated_section = usize::try_from(read_u32_elf(object, header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if read_u32_elf(object, header + 4)? != 4
            || read_u64_elf(object, header + 56)? != 24
            || usize::try_from(read_u32_elf(object, header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != symbols_index
            || !text_sections
                .get(relocated_section)
                .copied()
                .unwrap_or(false)
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let relocated_base = elf_combined_text_offset(
            object,
            section_offset,
            section_count,
            relocated_section,
            text_start,
            0,
        )?;
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        let record_count = records.len() / 24;
        if records.len() % 24 != 0
            || relocation_count
                .checked_add(record_count)
                .filter(|count| *count <= relocation_storage.len())
                .is_none()
        {
            return Err(LinkerError::TooManyRelocations);
        }
        for record in records.chunks_exact(24) {
            let offset = relocated_base
                .checked_add(to_usize_elf(read_u64_elf(record, 0)?)?)
                .ok_or(LinkerError::OffsetOverflow)?;
            offset
                .checked_add(4)
                .filter(|end| *end <= text.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            let info = read_u64_elf(record, 8)?;
            let relocation_type =
                u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)?;
            if relocation_type != 2 && relocation_type != 4 && relocation_type != 9 {
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
            if writable_sections
                .get(target_section)
                .copied()
                .unwrap_or(false)
            {
                if relocation_type != 2 {
                    return Err(LinkerError::UnsupportedElf);
                }
                continue;
            }
            let (target, addend) = if target_section == 0 {
                let symbol = elf_string(
                    strings,
                    usize::try_from(read_u32_elf(symbols, target_offset)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                )?;
                if relocation_type == 9 {
                    if offset < 2
                        || !matches!(text.get(offset - 2..offset), Some([0xff, 0x15 | 0x25]))
                    {
                        return Err(LinkerError::UnsupportedElf);
                    }
                    (
                        LinkRelocationTarget::GotPcRelativeSymbol(symbol),
                        encoded_addend,
                    )
                } else {
                    (LinkRelocationTarget::Symbol(symbol), encoded_addend)
                }
            } else if text_sections.get(target_section).copied().unwrap_or(false) {
                if relocation_type == 9 {
                    return Err(LinkerError::UnsupportedElf);
                }
                let text_offset = elf_combined_text_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    text_start,
                    read_u64_elf(symbols, target_offset + 8)?,
                )?;
                if text_offset > text.len() {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                (LinkRelocationTarget::InputText(text_offset), encoded_addend)
            } else if readonly_sections
                .get(target_section)
                .copied()
                .unwrap_or(false)
            {
                let symbol_data_offset = elf_readonly_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    readonly_start,
                    read_u64_elf(symbols, target_offset + 8)?,
                )?;
                if relocation_type == 9 {
                    let prefix = offset.checked_sub(3).ok_or(LinkerError::UnsupportedElf)?;
                    let instruction = text
                        .get(prefix..offset)
                        .ok_or(LinkerError::UnsupportedElf)?;
                    if instruction[0] != 0x48
                        || instruction[1] != 0x8b
                        || instruction[2] & 0xc7 != 0x05
                    {
                        return Err(LinkerError::UnsupportedElf);
                    }
                    if symbol_data_offset > readonly_data.len() {
                        return Err(LinkerError::InvalidRelocationOffset);
                    }
                    (
                        LinkRelocationTarget::GotPcRelativeReadonlyData(symbol_data_offset),
                        encoded_addend,
                    )
                } else {
                    let data_offset = i64::try_from(symbol_data_offset)
                        .map_err(|_| LinkerError::OffsetOverflow)?
                        .checked_add(encoded_addend)
                        .and_then(|value| value.checked_add(4))
                        .and_then(|value| usize::try_from(value).ok())
                        .ok_or(LinkerError::InvalidRelocationOffset)?;
                    if data_offset > readonly_data.len() {
                        return Err(LinkerError::InvalidRelocationOffset);
                    }
                    (LinkRelocationTarget::ReadonlyData(data_offset), -4)
                }
            } else {
                return Err(LinkerError::UnsupportedElf);
            };
            relocation_storage[relocation_count] = LinkRelocation {
                offset,
                target,
                addend,
            };
            relocation_count = relocation_count
                .checked_add(1)
                .ok_or(LinkerError::OffsetOverflow)?;
        }
    }
    for index in 1..section_count {
        if !data_relocation_sections[index] {
            continue;
        }
        let header = elf_section_header(section_offset, section_count, index)?;
        let relocated_section = usize::try_from(read_u32_elf(object, header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        let relocated_header =
            elf_section_header(section_offset, section_count, relocated_section)?;
        if read_u32_elf(object, relocated_header + 4)? != 1
            || !writable_sections
                .get(relocated_section)
                .copied()
                .unwrap_or(false)
            || usize::try_from(read_u32_elf(object, header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != symbols_index
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        if records.len() % 24 != 0 {
            return Err(LinkerError::InvalidElf);
        }
        for record in records.chunks_exact(24) {
            let info = read_u64_elf(record, 8)?;
            if u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)? != 1 {
                return Err(LinkerError::UnsupportedElf);
            }
            let target_index =
                usize::try_from(info >> 32).map_err(|_| LinkerError::OffsetOverflow)?;
            if target_index >= symbol_count {
                return Err(LinkerError::InvalidElf);
            }
            let target_offset = target_index * 24;
            if read_u16_elf(symbols, target_offset + 6)? != 0 {
                continue;
            }
            if *symbols
                .get(target_offset + 4)
                .ok_or(LinkerError::InvalidElf)?
                >> 4
                != 1
                || read_u64_elf(symbols, target_offset + 8)? != 0
            {
                return Err(LinkerError::UnsupportedElf);
            }
            if relocation_count == relocation_storage.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let symbol = elf_string(
                strings,
                usize::try_from(read_u32_elf(symbols, target_offset)?)
                    .map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
            relocation_storage[relocation_count] = LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::RequiredSymbol(symbol),
                addend: 0,
            };
            relocation_count += 1;
        }
    }
    Ok(LinkInput {
        symbol,
        symbol_target,
        additional_definitions: &definition_storage[..definition_count],
        text,
        readonly_data,
        relocations: &relocation_storage[..relocation_count],
    })
}

fn elf_combined_text_offset(
    object: &[u8],
    section_offset: usize,
    section_count: usize,
    section: usize,
    text_start: usize,
    value: u64,
) -> Result<usize, LinkerError> {
    let header = elf_section_header(section_offset, section_count, section)?;
    let raw = to_usize_elf(read_u64_elf(object, header + 24)?)?;
    let size = to_usize_elf(read_u64_elf(object, header + 32)?)?;
    let value = to_usize_elf(value)?;
    if value > size {
        return Err(LinkerError::InvalidElf);
    }
    raw.checked_sub(text_start)
        .and_then(|base| base.checked_add(value))
        .ok_or(LinkerError::OffsetOverflow)
}

/// Decodes the bounded `.eh_frame` subset emitted by the pinned x86-64
/// gnullvm oracle. The caller owns relocation storage so archive inputs remain
/// allocation-free and independently bounded.
pub fn decode_x86_64_elf_unwind<'data, 'relocations>(
    object: &'data [u8],
    relocation_storage: &'relocations mut [ElfUnwindRelocation; MAX_LINK_RELOCATIONS],
) -> Result<ElfUnwindData<'data, 'relocations>, LinkerError> {
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(object.get(7), Some(0 | 3))
        || object.get(8) != Some(&0)
        || read_u16_elf(object, 16)? != 1
        || read_u16_elf(object, 18)? != 62
        || read_u32_elf(object, 20)? != 1
        || read_u16_elf(object, 52)? != 64
        || read_u16_elf(object, 58)? != 64
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let section_names_index = usize::from(read_u16_elf(object, 62)?);
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) || section_names_index >= section_count {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_names =
        elf_section_contents(object, section_offset, section_count, section_names_index)?;
    let mut text_sections = [false; MAX_ELF_SECTIONS];
    let mut text_span = None;
    let mut unwind_index = None;
    let mut unwind_relocations_index = None;
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        let name = elf_string(
            section_names,
            usize::try_from(read_u32_elf(object, header)?)
                .map_err(|_| LinkerError::OffsetOverflow)?,
        )?;
        let contents = elf_section_contents(object, section_offset, section_count, index)?;
        if (name == ".text" || name.starts_with(".text.")) && !contents.is_empty() {
            let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
            let end = start
                .checked_add(contents.len())
                .ok_or(LinkerError::OffsetOverflow)?;
            text_sections[index] = true;
            text_span = Some(match text_span {
                None => (start, end),
                Some((first, previous_end))
                    if previous_end <= start
                        && object
                            .get(previous_end..start)
                            .map(|gap| gap.iter().all(|byte| *byte == 0))
                            .unwrap_or(false) =>
                {
                    (first, end)
                }
                Some(_) => return Err(LinkerError::UnsupportedElf),
            });
        } else if name == ".eh_frame" {
            if unwind_index.replace(index).is_some()
                || read_u32_elf(object, header + 4)? != 0x7000_0001
                || read_u64_elf(object, header + 8)? != 2
                || read_u64_elf(object, header + 48)? != 8
            {
                return Err(LinkerError::UnsupportedElf);
            }
        } else if name == ".rela.eh_frame" {
            if unwind_relocations_index.replace(index).is_some() {
                return Err(LinkerError::UnsupportedElf);
            }
        } else if name == ".symtab" && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let Some(unwind_index) = unwind_index else {
        if unwind_relocations_index.is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
        return Ok(ElfUnwindData {
            bytes: &object[0..0],
            relocations: &relocation_storage[..0],
        });
    };
    let unwind_relocations_index = unwind_relocations_index.ok_or(LinkerError::UnsupportedElf)?;
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let (text_start, text_end) = text_span.ok_or(LinkerError::InvalidElf)?;
    let text_length = text_end
        .checked_sub(text_start)
        .ok_or(LinkerError::OffsetOverflow)?;
    let unwind = elf_section_contents(object, section_offset, section_count, unwind_index)?;
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    let relocation_header =
        elf_section_header(section_offset, section_count, unwind_relocations_index)?;
    if read_u32_elf(object, relocation_header + 4)? != 4
        || read_u64_elf(object, relocation_header + 8)? != 0x40
        || read_u64_elf(object, relocation_header + 48)? != 8
        || read_u64_elf(object, relocation_header + 56)? != 24
        || usize::try_from(read_u32_elf(object, relocation_header + 40)?)
            .map_err(|_| LinkerError::OffsetOverflow)?
            != symbols_index
        || usize::try_from(read_u32_elf(object, relocation_header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?
            != unwind_index
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let records = elf_section_contents(
        object,
        section_offset,
        section_count,
        unwind_relocations_index,
    )?;
    if records.len() % 24 != 0 || records.len() / 24 > relocation_storage.len() {
        return Err(LinkerError::TooManyRelocations);
    }
    let mut previous_offset = None;
    for (index, record) in records.chunks_exact(24).enumerate() {
        let offset = to_usize_elf(read_u64_elf(record, 0)?)?;
        offset
            .checked_add(4)
            .filter(|end| *end <= unwind.len())
            .ok_or(LinkerError::InvalidRelocationOffset)?;
        if previous_offset.is_some_and(|previous| previous >= offset) {
            return Err(LinkerError::UnsupportedElf);
        }
        previous_offset = Some(offset);
        validate_elf_fde_field(unwind, offset)?;
        let info = read_u64_elf(record, 8)?;
        if u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)? != 2 {
            return Err(LinkerError::UnsupportedElf);
        }
        let symbol_index = usize::try_from(info >> 32).map_err(|_| LinkerError::OffsetOverflow)?;
        let symbol_offset = symbol_index
            .checked_mul(24)
            .filter(|offset| {
                offset
                    .checked_add(24)
                    .is_some_and(|end| end <= symbols.len())
            })
            .ok_or(LinkerError::InvalidElf)?;
        let target_section = usize::from(read_u16_elf(symbols, symbol_offset + 6)?);
        if !text_sections.get(target_section).copied().unwrap_or(false) {
            return Err(LinkerError::UnsupportedElf);
        }
        let target_text_offset = elf_combined_text_offset(
            object,
            section_offset,
            section_count,
            target_section,
            text_start,
            read_u64_elf(symbols, symbol_offset + 8)?,
        )?;
        if target_text_offset > text_length {
            return Err(LinkerError::InvalidRelocationOffset);
        }
        relocation_storage[index] = ElfUnwindRelocation {
            offset,
            target_text_offset,
            addend: read_i64_elf(record, 16)?,
        };
    }
    Ok(ElfUnwindData {
        bytes: unwind,
        relocations: &relocation_storage[..records.len() / 24],
    })
}

fn validate_elf_fde_field(unwind: &[u8], offset: usize) -> Result<(), LinkerError> {
    let fde = offset
        .checked_sub(8)
        .ok_or(LinkerError::InvalidRelocationOffset)?;
    let raw_fde_length = read_u32_elf(unwind, fde)?;
    let fde_length = usize::try_from(raw_fde_length).map_err(|_| LinkerError::OffsetOverflow)?;
    if fde_length < 12 || raw_fde_length == u32::MAX {
        return Err(LinkerError::UnsupportedElf);
    }
    fde.checked_add(4)
        .and_then(|end| end.checked_add(fde_length))
        .filter(|end| *end <= unwind.len())
        .ok_or(LinkerError::InvalidElf)?;
    let cie_field = fde.checked_add(4).ok_or(LinkerError::OffsetOverflow)?;
    let cie_distance = usize::try_from(read_u32_elf(unwind, cie_field)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    let cie = cie_field
        .checked_sub(cie_distance)
        .ok_or(LinkerError::InvalidElf)?;
    let cie_length =
        usize::try_from(read_u32_elf(unwind, cie)?).map_err(|_| LinkerError::OffsetOverflow)?;
    if cie_distance == 0
        || cie_length < 4
        || read_u32_elf(unwind, cie + 4)? != 0
        || cie
            .checked_add(4)
            .and_then(|end| end.checked_add(cie_length))
            .filter(|end| *end <= unwind.len())
            .is_none()
    {
        return Err(LinkerError::UnsupportedElf);
    }
    Ok(())
}

pub fn decode_x86_64_elf_writable<'data, 'relocations>(
    object: &'data [u8],
    reference_storage: &'relocations mut [ElfWritableReference; MAX_LINK_RELOCATIONS],
    absolute_storage: &'relocations mut [ElfWritableAbsoluteRelocation<'data>;
                          MAX_LINK_RELOCATIONS],
) -> Result<ElfWritableData<'data, 'relocations>, LinkerError> {
    if object.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(object.get(7), Some(0 | 3))
        || object.get(8) != Some(&0)
        || read_u16_elf(object, 16)? != 1
        || read_u16_elf(object, 18)? != 62
        || read_u32_elf(object, 20)? != 1
        || read_u16_elf(object, 52)? != 64
        || read_u16_elf(object, 58)? != 64
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_offset = to_usize_elf(read_u64_elf(object, 40)?)?;
    let section_count = usize::from(read_u16_elf(object, 60)?);
    let section_names_index = usize::from(read_u16_elf(object, 62)?);
    if !(4..=MAX_ELF_SECTIONS).contains(&section_count) || section_names_index >= section_count {
        return Err(LinkerError::UnsupportedElf);
    }
    let section_names =
        elf_section_contents(object, section_offset, section_count, section_names_index)?;
    let mut text_sections = [false; MAX_ELF_SECTIONS];
    let mut readonly_sections = [false; MAX_ELF_SECTIONS];
    let mut data_sections = [false; MAX_ELF_SECTIONS];
    let mut bss_sections = [false; MAX_ELF_SECTIONS];
    let mut bss_offsets = [0usize; MAX_ELF_SECTIONS];
    let mut relocation_sections = [false; MAX_ELF_SECTIONS];
    let mut data_relocation_sections = [false; MAX_ELF_SECTIONS];
    let mut text_span = None;
    let mut readonly_span = None;
    let mut data_span = None;
    let mut initialized_alignment = 1usize;
    let mut zeroed_alignment = 1usize;
    let mut symbols_index = None;
    for index in 1..section_count {
        let header = elf_section_header(section_offset, section_count, index)?;
        let name = elf_string(
            section_names,
            usize::try_from(read_u32_elf(object, header)?)
                .map_err(|_| LinkerError::OffsetOverflow)?,
        )?;
        let section_type = read_u32_elf(object, header + 4)?;
        if name == ".text" || name.starts_with(".text.") {
            if section_type != 1 || read_u64_elf(object, header + 8)? != 6 {
                return Err(LinkerError::UnsupportedElf);
            }
            let contents = elf_section_contents(object, section_offset, section_count, index)?;
            if !contents.is_empty() {
                let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
                let end = start
                    .checked_add(contents.len())
                    .ok_or(LinkerError::OffsetOverflow)?;
                text_sections[index] = true;
                text_span = Some(extend_elf_zero_span(object, text_span, start, end)?);
            }
        } else if name == ".rodata" || name.starts_with(".rodata.") {
            if section_type != 1 || read_u64_elf(object, header + 8)? & 2 == 0 {
                return Err(LinkerError::UnsupportedElf);
            }
            let contents = elf_section_contents(object, section_offset, section_count, index)?;
            readonly_sections[index] = true;
            if !contents.is_empty() {
                let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
                let end = start
                    .checked_add(contents.len())
                    .ok_or(LinkerError::OffsetOverflow)?;
                readonly_span = Some(extend_elf_zero_span(object, readonly_span, start, end)?);
            } else {
                let alignment = read_u64_elf(object, header + 48)?;
                if !matches!(alignment, 1..=16) || !alignment.is_power_of_two() {
                    return Err(LinkerError::UnsupportedElf);
                }
            }
        } else if name == ".data" || name.starts_with(".data.") {
            if section_type != 1 || read_u64_elf(object, header + 8)? != 3 {
                return Err(LinkerError::UnsupportedElf);
            }
            let contents = elf_section_contents(object, section_offset, section_count, index)?;
            let alignment = to_usize_elf(read_u64_elf(object, header + 48)?)?;
            if alignment == 0 || !alignment.is_power_of_two() || alignment > 0x1000 {
                return Err(LinkerError::UnsupportedElf);
            }
            initialized_alignment = initialized_alignment.max(alignment);
            if !contents.is_empty() {
                let start = to_usize_elf(read_u64_elf(object, header + 24)?)?;
                let end = start
                    .checked_add(contents.len())
                    .ok_or(LinkerError::OffsetOverflow)?;
                data_sections[index] = true;
                data_span = Some(extend_elf_zero_span(object, data_span, start, end)?);
            }
        } else if name == ".bss" || name.starts_with(".bss.") {
            if section_type != 8 || read_u64_elf(object, header + 8)? != 3 {
                return Err(LinkerError::UnsupportedElf);
            }
            bss_sections[index] = true;
        } else if name == ".rela.text" || name.starts_with(".rela.text.") {
            relocation_sections[index] = true;
        } else if name == ".rela.data" || name.starts_with(".rela.data.") {
            data_relocation_sections[index] = true;
        } else if name == ".symtab" && symbols_index.replace(index).is_some() {
            return Err(LinkerError::UnsupportedElf);
        }
    }
    let initialized = match data_span {
        Some((start, end)) => object.get(start..end).ok_or(LinkerError::InvalidElf)?,
        None => &object[0..0],
    };
    let mut zeroed_size = 0usize;
    for index in 1..section_count {
        if !bss_sections[index] {
            continue;
        }
        let header = elf_section_header(section_offset, section_count, index)?;
        let alignment = to_usize_elf(read_u64_elf(object, header + 48)?)?;
        if alignment == 0 || !alignment.is_power_of_two() || alignment > 0x1000 {
            return Err(LinkerError::UnsupportedElf);
        }
        zeroed_alignment = zeroed_alignment.max(alignment);
        zeroed_size = align(zeroed_size, alignment)?;
        bss_offsets[index] = zeroed_size;
        zeroed_size = zeroed_size
            .checked_add(to_usize_elf(read_u64_elf(object, header + 32)?)?)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if initialized.is_empty() && zeroed_size == 0 {
        return Ok(ElfWritableData {
            initialized,
            initialized_alignment,
            zeroed_size,
            zeroed_alignment,
            references: &reference_storage[..0],
            absolute_relocations: &absolute_storage[..0],
        });
    }
    let (text_start, text_end) = text_span.ok_or(LinkerError::InvalidElf)?;
    let text_length = text_end
        .checked_sub(text_start)
        .ok_or(LinkerError::OffsetOverflow)?;
    let symbols_index = symbols_index.ok_or(LinkerError::InvalidElf)?;
    let symbols_header = elf_section_header(section_offset, section_count, symbols_index)?;
    let strings_index = usize::try_from(read_u32_elf(object, symbols_header + 40)?)
        .map_err(|_| LinkerError::OffsetOverflow)?;
    if read_u32_elf(object, symbols_header + 4)? != 2
        || read_u64_elf(object, symbols_header + 56)? != 24
        || strings_index >= section_count
        || read_u32_elf(
            object,
            elf_section_header(section_offset, section_count, strings_index)? + 4,
        )? != 3
    {
        return Err(LinkerError::UnsupportedElf);
    }
    let strings = elf_section_contents(object, section_offset, section_count, strings_index)?;
    let symbols = elf_section_contents(object, section_offset, section_count, symbols_index)?;
    if symbols.len() % 24 != 0 {
        return Err(LinkerError::InvalidElf);
    }
    let symbol_count = symbols.len() / 24;
    let mut reference_count = 0usize;
    for index in 1..section_count {
        if !relocation_sections[index] {
            continue;
        }
        let header = elf_section_header(section_offset, section_count, index)?;
        let relocated_section = usize::try_from(read_u32_elf(object, header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if read_u32_elf(object, header + 4)? != 4
            || read_u64_elf(object, header + 56)? != 24
            || usize::try_from(read_u32_elf(object, header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != symbols_index
            || !text_sections
                .get(relocated_section)
                .copied()
                .unwrap_or(false)
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let relocated_base = elf_combined_text_offset(
            object,
            section_offset,
            section_count,
            relocated_section,
            text_start,
            0,
        )?;
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        if records.len() % 24 != 0 {
            return Err(LinkerError::InvalidElf);
        }
        for record in records.chunks_exact(24) {
            let info = read_u64_elf(record, 8)?;
            let symbol_index =
                usize::try_from(info >> 32).map_err(|_| LinkerError::OffsetOverflow)?;
            if symbol_index >= symbol_count {
                return Err(LinkerError::InvalidElf);
            }
            let symbol_offset = symbol_index * 24;
            let target_section = usize::from(read_u16_elf(symbols, symbol_offset + 6)?);
            let target = if data_sections.get(target_section).copied().unwrap_or(false) {
                let start = data_span.ok_or(LinkerError::InvalidElf)?.0;
                let offset = elf_combined_text_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    start,
                    read_u64_elf(symbols, symbol_offset + 8)?,
                )?;
                if offset > initialized.len() {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableTarget::Initialized(offset)
            } else if bss_sections.get(target_section).copied().unwrap_or(false) {
                let value = to_usize_elf(read_u64_elf(symbols, symbol_offset + 8)?)?;
                let section_header =
                    elf_section_header(section_offset, section_count, target_section)?;
                if value > to_usize_elf(read_u64_elf(object, section_header + 32)?)? {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableTarget::Zeroed(
                    bss_offsets[target_section]
                        .checked_add(value)
                        .ok_or(LinkerError::OffsetOverflow)?,
                )
            } else {
                continue;
            };
            if u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)? != 2 {
                return Err(LinkerError::UnsupportedElf);
            }
            if reference_count == reference_storage.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let text_offset = relocated_base
                .checked_add(to_usize_elf(read_u64_elf(record, 0)?)?)
                .ok_or(LinkerError::OffsetOverflow)?;
            text_offset
                .checked_add(4)
                .filter(|end| *end <= text_length)
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            reference_storage[reference_count] = ElfWritableReference {
                text_offset,
                target,
                addend: read_i64_elf(record, 16)?,
            };
            reference_count += 1;
        }
    }
    let mut absolute_count = 0usize;
    for index in 1..section_count {
        if !data_relocation_sections[index] {
            continue;
        }
        let header = elf_section_header(section_offset, section_count, index)?;
        let relocated_section = usize::try_from(read_u32_elf(object, header + 44)?)
            .map_err(|_| LinkerError::OffsetOverflow)?;
        if read_u32_elf(object, header + 4)? != 4
            || read_u64_elf(object, header + 8)? & 0x40 == 0
            || read_u64_elf(object, header + 56)? != 24
            || usize::try_from(read_u32_elf(object, header + 40)?)
                .map_err(|_| LinkerError::OffsetOverflow)?
                != symbols_index
            || !data_sections
                .get(relocated_section)
                .copied()
                .unwrap_or(false)
        {
            return Err(LinkerError::UnsupportedElf);
        }
        let data_start = data_span.ok_or(LinkerError::InvalidElf)?.0;
        let relocated_base = elf_combined_text_offset(
            object,
            section_offset,
            section_count,
            relocated_section,
            data_start,
            0,
        )?;
        let records = elf_section_contents(object, section_offset, section_count, index)?;
        if records.len() % 24 != 0 {
            return Err(LinkerError::InvalidElf);
        }
        for record in records.chunks_exact(24) {
            let info = read_u64_elf(record, 8)?;
            if u32::try_from(info & 0xffff_ffff).map_err(|_| LinkerError::OffsetOverflow)? != 1 {
                return Err(LinkerError::UnsupportedElf);
            }
            let symbol_index =
                usize::try_from(info >> 32).map_err(|_| LinkerError::OffsetOverflow)?;
            if symbol_index >= symbol_count {
                return Err(LinkerError::InvalidElf);
            }
            let symbol_offset = symbol_index * 24;
            let target_section = usize::from(read_u16_elf(symbols, symbol_offset + 6)?);
            let target_value = read_u64_elf(symbols, symbol_offset + 8)?;
            let target = if readonly_sections
                .get(target_section)
                .copied()
                .unwrap_or(false)
            {
                ElfWritableAbsoluteTarget::ReadonlyData(elf_readonly_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    readonly_span.map(|span| span.0),
                    target_value,
                )?)
            } else if text_sections.get(target_section).copied().unwrap_or(false) {
                ElfWritableAbsoluteTarget::InputText(elf_combined_text_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    text_start,
                    target_value,
                )?)
            } else if data_sections.get(target_section).copied().unwrap_or(false) {
                ElfWritableAbsoluteTarget::Initialized(elf_combined_text_offset(
                    object,
                    section_offset,
                    section_count,
                    target_section,
                    data_start,
                    target_value,
                )?)
            } else if bss_sections.get(target_section).copied().unwrap_or(false) {
                let value = to_usize_elf(target_value)?;
                let section_header =
                    elf_section_header(section_offset, section_count, target_section)?;
                if value > to_usize_elf(read_u64_elf(object, section_header + 32)?)? {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableAbsoluteTarget::Zeroed(
                    bss_offsets[target_section]
                        .checked_add(value)
                        .ok_or(LinkerError::OffsetOverflow)?,
                )
            } else if target_section == 0 {
                if *symbols
                    .get(symbol_offset + 4)
                    .ok_or(LinkerError::InvalidElf)?
                    >> 4
                    != 1
                    || target_value != 0
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                ElfWritableAbsoluteTarget::Symbol(elf_string(
                    strings,
                    usize::try_from(read_u32_elf(symbols, symbol_offset)?)
                        .map_err(|_| LinkerError::OffsetOverflow)?,
                )?)
            } else {
                return Err(LinkerError::UnsupportedElf);
            };
            if absolute_count == absolute_storage.len() {
                return Err(LinkerError::TooManyRelocations);
            }
            let offset = relocated_base
                .checked_add(to_usize_elf(read_u64_elf(record, 0)?)?)
                .ok_or(LinkerError::OffsetOverflow)?;
            offset
                .checked_add(8)
                .filter(|end| *end <= initialized.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            absolute_storage[absolute_count] = ElfWritableAbsoluteRelocation {
                offset,
                target,
                addend: read_i64_elf(record, 16)?,
            };
            absolute_count += 1;
        }
    }
    Ok(ElfWritableData {
        initialized,
        initialized_alignment,
        zeroed_size,
        zeroed_alignment,
        references: &reference_storage[..reference_count],
        absolute_relocations: &absolute_storage[..absolute_count],
    })
}

fn elf_readonly_offset(
    object: &[u8],
    section_offset: usize,
    section_count: usize,
    section: usize,
    readonly_start: Option<usize>,
    value: u64,
) -> Result<usize, LinkerError> {
    let header = elf_section_header(section_offset, section_count, section)?;
    let size = read_u64_elf(object, header + 32)?;
    if size == 0 {
        let alignment = read_u64_elf(object, header + 48)?;
        if value != 0 || !matches!(alignment, 1..=16) || !alignment.is_power_of_two() {
            return Err(LinkerError::InvalidRelocationOffset);
        }
        return Ok(0);
    }
    elf_combined_text_offset(
        object,
        section_offset,
        section_count,
        section,
        readonly_start.ok_or(LinkerError::InvalidElf)?,
        value,
    )
}

fn extend_elf_zero_span(
    object: &[u8],
    span: Option<(usize, usize)>,
    start: usize,
    end: usize,
) -> Result<(usize, usize), LinkerError> {
    match span {
        None => Ok((start, end)),
        Some((first, previous_end))
            if previous_end <= start
                && object
                    .get(previous_end..start)
                    .is_some_and(|gap| gap.iter().all(|byte| *byte == 0)) =>
        {
            Ok((first, end))
        }
        Some(_) => Err(LinkerError::UnsupportedElf),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
    text_length: usize,
    readonly_offset: usize,
    entry_offset: usize,
    layouts: [InputLayout; MAX_LINK_FRAGMENTS],
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
    link_x86_64_pe_with_data_unwind_and_readonly_relocations::<MAX_IMAGE_BYTES, MAX_LINKED_BYTES>(
        inputs,
        entry_symbol,
        runtime_functions,
        writable_data,
        &[],
    )
}

pub fn link_x86_64_pe_with_data_unwind_and_readonly_relocations<
    const MAX_IMAGE_BYTES: usize,
    const MAX_LINKED_BYTES: usize,
>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
    readonly_absolute_relocations: &[PeReadonlyAbsoluteRelocation<'_>],
) -> Result<PeImage<MAX_IMAGE_BYTES>, LinkerError> {
    let mut bytes = [0u8; MAX_IMAGE_BYTES];
    let length = link_x86_64_pe_with_data_unwind_and_readonly_relocations_into::<
        MAX_LINKED_BYTES,
    >(
        inputs,
        entry_symbol,
        runtime_functions,
        writable_data,
        readonly_absolute_relocations,
        &mut bytes,
    )?;
    Ok(PeImage { bytes, length })
}

/// Serializes a bounded PE image into caller-owned storage. Hosted drivers use
/// this entry point so multi-megabyte output tiers do not become process-stack
/// arrays; fixed-array callers retain the convenience wrapper above.
pub fn link_x86_64_pe_with_data_unwind_and_readonly_relocations_into<
    const MAX_LINKED_BYTES: usize,
>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
    readonly_absolute_relocations: &[PeReadonlyAbsoluteRelocation<'_>],
    bytes: &mut [u8],
) -> Result<usize, LinkerError> {
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
    if readonly_absolute_relocations.len() > MAX_PE_READONLY_RELOCATIONS {
        return Err(LinkerError::TooManyRelocations);
    }
    let text_size = linked.text_length;
    let linked_readonly_size = linked.length - linked.readonly_offset;
    let mut unwind_offsets = [0usize; MAX_PE_RUNTIME_FUNCTIONS];
    let mut readonly_size = linked_readonly_size;
    for (index, function) in runtime_functions.iter().enumerate() {
        if function.begin_identity.is_none() {
            validate_symbol(function.begin_symbol)?;
        }
        if function.end_identity.is_none() {
            validate_symbol(function.end_symbol)?;
        }
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
    let mut writable_kept = [false; MAX_LINK_INPUTS];
    for (index, data) in writable_data.iter().enumerate() {
        validate_symbol(data.symbol)?;
        if let Some((_, earlier)) =
            writable_data[..index]
                .iter()
                .enumerate()
                .find(|(earlier_index, earlier)| {
                    writable_kept[*earlier_index] && earlier.symbol == data.symbol
                })
        {
            if earlier.selection != PeWritableComdatSelection::Any
                || data.selection != PeWritableComdatSelection::Any
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        } else {
            writable_kept[index] = true;
        }
    }
    let mut writable_offsets = [0usize; MAX_LINK_INPUTS];
    let mut writable_size = 0usize;
    for (index, data) in writable_data.iter().enumerate() {
        if !writable_kept[index] {
            continue;
        }
        if data.initialized.is_empty() || data.zeroed_size != 0 {
            continue;
        }
        writable_size = align(writable_size, 8)?;
        writable_offsets[index] = writable_size;
        writable_size = writable_size
            .checked_add(data.initialized.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        for relocation in data.relocations {
            match relocation.target {
                PeWritableRelocationTarget::Readonly { owner, .. } => validate_symbol(owner)?,
                PeWritableRelocationTarget::CoffSection { .. } => {}
                PeWritableRelocationTarget::TextSymbol(symbol) => validate_symbol(symbol)?,
                PeWritableRelocationTarget::TlsSection { .. } => {
                    return Err(LinkerError::UnsupportedCoffTls);
                }
                PeWritableRelocationTarget::WritableSymbol(symbol) => validate_symbol(symbol)?,
            }
            relocation
                .offset
                .checked_add(8)
                .filter(|end| *end <= data.initialized.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
        }
    }
    let writable_file_size = writable_size;
    let mut zeroed_total = 0usize;
    for (index, data) in writable_data.iter().enumerate() {
        if !writable_kept[index] {
            continue;
        }
        if !data.initialized.is_empty() {
            continue;
        }
        if data.zeroed_size == 0 || !data.relocations.is_empty() {
            return Err(LinkerError::InvalidCoff);
        }
        writable_size = align(writable_size, 8)?;
        writable_offsets[index] = writable_size;
        writable_size = writable_size
            .checked_add(data.zeroed_size)
            .ok_or(LinkerError::OffsetOverflow)?;
        zeroed_total = zeroed_total
            .checked_add(data.zeroed_size)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let text_raw_size = align(text_size, FILE_ALIGNMENT)?;
    let readonly_raw_size = align(readonly_size, FILE_ALIGNMENT)?;
    let readonly_raw = HEADERS
        .checked_add(text_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    let writable_raw_size = align(writable_file_size, FILE_ALIGNMENT)?;
    let writable_raw = readonly_raw
        .checked_add(readonly_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    let length = writable_raw
        .checked_add(writable_raw_size)
        .ok_or(LinkerError::OffsetOverflow)?;
    if length > bytes.len() {
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

    bytes.fill(0);
    bytes[0..2].copy_from_slice(b"MZ");
    patch_u32(bytes, 0x3c, 0x80)?;
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    patch_u16(bytes, 0x84, 0x8664)?;
    let section_count = 1 + usize::from(readonly_size != 0) + usize::from(writable_size != 0);
    patch_u16(
        bytes,
        0x86,
        u16::try_from(section_count).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u16(bytes, 0x94, 240)?;
    patch_u16(bytes, 0x96, 0x022f)?;

    let optional = 0x98;
    patch_u16(bytes, optional, 0x20b)?;
    patch_u32(bytes, optional + 4, to_u32_link(text_raw_size)?)?;
    patch_u32(
        bytes,
        optional + 8,
        to_u32_link(
            readonly_raw_size
                .checked_add(writable_raw_size)
                .ok_or(LinkerError::OffsetOverflow)?,
        )?,
    )?;
    patch_u32(bytes, optional + 12, to_u32_link(zeroed_total)?)?;
    patch_u32(
        bytes,
        optional + 16,
        to_u32_link(TEXT_RVA + linked.entry_offset)?,
    )?;
    patch_u32(bytes, optional + 20, to_u32_link(TEXT_RVA)?)?;
    patch_u64(
        bytes,
        optional + 24,
        u64::try_from(IMAGE_BASE).map_err(|_| LinkerError::OffsetOverflow)?,
    )?;
    patch_u32(bytes, optional + 32, to_u32_link(SECTION_ALIGNMENT)?)?;
    patch_u32(bytes, optional + 36, to_u32_link(FILE_ALIGNMENT)?)?;
    patch_u16(bytes, optional + 40, 6)?;
    patch_u16(bytes, optional + 48, 6)?;
    patch_u32(bytes, optional + 56, to_u32_link(size_of_image)?)?;
    patch_u32(bytes, optional + 60, to_u32_link(HEADERS)?)?;
    patch_u16(bytes, optional + 68, 3)?;
    patch_u16(bytes, optional + 70, 0x8100)?;
    patch_u64(bytes, optional + 72, 0x10_0000)?;
    patch_u64(bytes, optional + 80, 0x1000)?;
    patch_u64(bytes, optional + 88, 0x10_0000)?;
    patch_u64(bytes, optional + 96, 0x1000)?;
    patch_u32(bytes, optional + 108, 16)?;
    if !runtime_functions.is_empty() {
        patch_u32(
            bytes,
            optional + 136,
            to_u32_link(readonly_rva + pdata_offset)?,
        )?;
        patch_u32(
            bytes,
            optional + 140,
            to_u32_link(runtime_functions.len() * 12)?,
        )?;
    }

    write_pe_section(
        bytes,
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
            bytes,
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
            bytes,
            if readonly_size == 0 { 0x1b0 } else { 0x1d8 },
            b".data\0\0\0",
            writable_size,
            writable_rva,
            writable_raw_size,
            writable_raw,
            0xc000_0040,
        )?;
    }
    copy_at(bytes, HEADERS, &linked.bytes[..linked.text_length])?;
    if readonly_size != 0 {
        copy_at(
            bytes,
            readonly_raw,
            &linked.bytes[linked.readonly_offset..linked.length],
        )?;
    }
    let mut begin_rvas = [0u32; MAX_PE_RUNTIME_FUNCTIONS];
    let mut end_rvas = [0u32; MAX_PE_RUNTIME_FUNCTIONS];
    let mut order = [0usize; MAX_PE_RUNTIME_FUNCTIONS];
    for (index, function) in runtime_functions.iter().enumerate() {
        let begin = match function.begin_identity {
            Some(identity) => resolve_coff_section(
                inputs,
                &linked.layouts,
                identity,
                function.begin_offset,
            )?,
            None => resolve_symbol(inputs, &linked.layouts, function.begin_symbol)?
                .checked_add(function.begin_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
        }
            .checked_add(TEXT_RVA)
            .ok_or(LinkerError::OffsetOverflow)?;
        let end = match function.end_identity {
            Some(identity) => resolve_coff_section(
                inputs,
                &linked.layouts,
                identity,
                function.end_offset,
            )?,
            None => resolve_symbol(inputs, &linked.layouts, function.end_symbol)?
                .checked_add(function.end_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
        }
            .checked_add(TEXT_RVA)
            .ok_or(LinkerError::OffsetOverflow)?;
        if end <= begin {
            return Err(LinkerError::InvalidRelocationOffset);
        }
        begin_rvas[index] = to_u32_link(begin)?;
        end_rvas[index] = to_u32_link(end)?;
        order[index] = index;
        copy_at(
            bytes,
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
        patch_u32(bytes, output, begin_rvas[*function_index])?;
        patch_u32(bytes, output + 4, end_rvas[*function_index])?;
        patch_u32(
            bytes,
            output + 8,
            to_u32_link(readonly_rva + unwind_offsets[*function_index])?,
        )?;
    }
    let writable_index = |symbol: &str| {
        writable_data
            .iter()
            .enumerate()
            .find(|(index, data)| writable_kept[*index] && data.symbol == symbol)
            .map(|(index, _)| index)
            .ok_or(LinkerError::UndefinedSymbol)
    };
    for (index, data) in writable_data.iter().enumerate() {
        if !writable_kept[index] || data.initialized.is_empty() {
            continue;
        }
        let output = writable_raw + writable_offsets[index];
        copy_at(bytes, output, data.initialized)?;
        for relocation in data.relocations {
            let target_rva = match relocation.target {
                PeWritableRelocationTarget::Readonly { owner, offset } => resolve_readonly_symbol(
                    inputs,
                    &linked.layouts,
                    linked.readonly_offset,
                    readonly_rva,
                    owner,
                    offset,
                )?,
                PeWritableRelocationTarget::CoffSection { identity, offset } => {
                    let target = resolve_coff_section(inputs, &linked.layouts, identity, offset)?;
                    readonly_rva
                        .checked_add(
                            target
                                .checked_sub(linked.readonly_offset)
                                .ok_or(LinkerError::OffsetOverflow)?,
                        )
                        .ok_or(LinkerError::OffsetOverflow)?
                }
                PeWritableRelocationTarget::TextSymbol(symbol) => TEXT_RVA
                    .checked_add(resolve_symbol(inputs, &linked.layouts, symbol)?)
                    .ok_or(LinkerError::OffsetOverflow)?,
                PeWritableRelocationTarget::TlsSection { .. } => unreachable!(),
                PeWritableRelocationTarget::WritableSymbol(symbol) => {
                    let target_index = writable_index(symbol)?;
                    writable_rva
                        .checked_add(writable_offsets[target_index])
                        .ok_or(LinkerError::OffsetOverflow)?
                }
            };
            let target = IMAGE_BASE
                .checked_add(target_rva)
                .ok_or(LinkerError::OffsetOverflow)?;
            patch_u64(
                bytes,
                output + relocation.offset,
                u64::try_from(target).map_err(|_| LinkerError::OffsetOverflow)?,
            )?;
        }
    }
    for relocation in readonly_absolute_relocations {
        if relocation.readonly_identity.is_none() {
            validate_symbol(relocation.readonly_owner)?;
        }
        if relocation.target_identity.is_none() {
            validate_symbol(relocation.target_symbol)?;
        }
        let pointer_rva = match relocation.readonly_identity {
            Some(identity) => {
                let target = resolve_coff_section(
                    inputs,
                    &linked.layouts,
                    identity,
                    relocation.readonly_offset,
                )?;
                readonly_rva
                    .checked_add(
                        target
                            .checked_sub(linked.readonly_offset)
                            .ok_or(LinkerError::OffsetOverflow)?,
                    )
                    .ok_or(LinkerError::OffsetOverflow)?
            }
            None => resolve_readonly_symbol(
                inputs,
                &linked.layouts,
                linked.readonly_offset,
                readonly_rva,
                relocation.readonly_owner,
                relocation.readonly_offset,
            )?,
        };
        let pointer_offset = readonly_raw
            .checked_add(
                pointer_rva
                    .checked_sub(readonly_rva)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        let target_rva = if let Some(identity) = relocation.target_identity {
            let target = resolve_coff_section(
                inputs,
                &linked.layouts,
                identity,
                relocation.target_offset,
            )?;
            if target < linked.readonly_offset {
                TEXT_RVA
                    .checked_add(target)
                    .ok_or(LinkerError::OffsetOverflow)?
            } else {
                readonly_rva
                    .checked_add(target - linked.readonly_offset)
                    .ok_or(LinkerError::OffsetOverflow)?
            }
        } else {
            match resolve_symbol(inputs, &linked.layouts, relocation.target_symbol) {
                Ok(offset) => TEXT_RVA
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                Err(LinkerError::UndefinedSymbol) => {
                    let target_index = writable_index(relocation.target_symbol)?;
                    writable_rva
                        .checked_add(writable_offsets[target_index])
                        .ok_or(LinkerError::OffsetOverflow)?
                }
                Err(error) => return Err(error),
            }
        };
        match relocation.kind {
            PeReadonlyRelocationKind::Address64 => {
                let target = i128::try_from(IMAGE_BASE)
                    .map_err(|_| LinkerError::OffsetOverflow)?
                    .checked_add(
                        i128::try_from(target_rva).map_err(|_| LinkerError::OffsetOverflow)?,
                    )
                    .and_then(|address| address.checked_add(i128::from(relocation.addend)))
                    .and_then(|address| u64::try_from(address).ok())
                    .ok_or(LinkerError::OffsetOverflow)?;
                patch_u64(bytes, pointer_offset, target)?;
            }
            PeReadonlyRelocationKind::Address32NoBase => {
                let target = i128::try_from(target_rva)
                    .map_err(|_| LinkerError::OffsetOverflow)?
                    .checked_add(i128::from(relocation.addend))
                    .and_then(|address| u32::try_from(address).ok())
                    .ok_or(LinkerError::RelocationOverflow)?;
                patch_u32(bytes, pointer_offset, target)?;
            }
            PeReadonlyRelocationKind::Relative32 { trailing_bytes } => {
                if trailing_bytes > 5 {
                    return Err(LinkerError::InvalidCoff);
                }
                let place_end_rva = pointer_rva
                    .checked_add(4)
                    .and_then(|value| value.checked_add(usize::from(trailing_bytes)))
                    .ok_or(LinkerError::OffsetOverflow)?;
                let displacement = i128::try_from(target_rva)
                    .map_err(|_| LinkerError::OffsetOverflow)?
                    .checked_add(i128::from(relocation.addend))
                    .and_then(|target| target.checked_sub(i128::try_from(place_end_rva).ok()?))
                    .and_then(|value| i32::try_from(value).ok())
                    .ok_or(LinkerError::RelocationOverflow)?;
                patch_i32(bytes, pointer_offset, displacement)?;
            }
        }
    }
    for (input, layout) in inputs.iter().zip(linked.layouts.iter()) {
        for relocation in input.relocations {
            let LinkRelocationTarget::PeWritableSymbol(symbol) = relocation.target else {
                continue;
            };
            let writable_index = writable_index(symbol)?;
            let place = layout
                .text
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target_rva = writable_rva
                .checked_add(writable_offsets[writable_index])
                .ok_or(LinkerError::OffsetOverflow)?;
            let place_rva = TEXT_RVA
                .checked_add(place)
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement = i64::try_from(target_rva)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(relocation.addend)
                .and_then(|value| value.checked_sub(i64::try_from(place_rva).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            patch_i32(
                bytes,
                HEADERS
                    .checked_add(place)
                    .ok_or(LinkerError::OffsetOverflow)?,
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?,
            )?;
        }
    }
    Ok(length)
}

/// Links MRML fragments into a deterministic, fixed-address, import-free
/// x86-64 ELF executable with page-separated load permissions.
pub fn link_x86_64_elf_executable<const MAX_IMAGE_BYTES: usize, const MAX_LINKED_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
) -> Result<ElfImage<MAX_IMAGE_BYTES>, LinkerError> {
    link_x86_64_elf_executable_with_unwind::<MAX_IMAGE_BYTES, MAX_LINKED_BYTES>(
        inputs,
        &[],
        entry_symbol,
    )
}

pub fn link_x86_64_elf_executable_with_unwind<
    const MAX_IMAGE_BYTES: usize,
    const MAX_LINKED_BYTES: usize,
>(
    inputs: &[LinkInput<'_, '_, '_>],
    unwind: &[ElfUnwindData<'_, '_>],
    entry_symbol: &str,
) -> Result<ElfImage<MAX_IMAGE_BYTES>, LinkerError> {
    link_x86_64_elf_executable_with_unwind_and_writable::<MAX_IMAGE_BYTES, MAX_LINKED_BYTES>(
        inputs,
        unwind,
        &[],
        entry_symbol,
    )
}

pub fn link_x86_64_elf_executable_with_unwind_and_writable<
    const MAX_IMAGE_BYTES: usize,
    const MAX_LINKED_BYTES: usize,
>(
    inputs: &[LinkInput<'_, '_, '_>],
    unwind: &[ElfUnwindData<'_, '_>],
    writable: &[ElfWritableData<'_, '_>],
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
    if !unwind.is_empty() && unwind.len() != inputs.len() {
        return Err(LinkerError::InvalidElf);
    }
    if !writable.is_empty() && writable.len() != inputs.len() {
        return Err(LinkerError::InvalidElf);
    }
    let base_length = if readonly_size == 0 {
        TEXT_OFFSET
            .checked_add(linked.text_length)
            .ok_or(LinkerError::OffsetOverflow)?
    } else {
        readonly_offset
            .checked_add(readonly_size)
            .ok_or(LinkerError::OffsetOverflow)?
    };
    let has_unwind = unwind.iter().any(|data| !data.bytes.is_empty());
    let frame_count = unwind
        .iter()
        .try_fold(0usize, |count, data| {
            count.checked_add(data.relocations.len())
        })
        .ok_or(LinkerError::OffsetOverflow)?;
    if frame_count > MAX_LINK_RELOCATIONS {
        return Err(LinkerError::TooManyRelocations);
    }
    let frame_header_size = if frame_count == 0 {
        0
    } else {
        12usize
            .checked_add(
                frame_count
                    .checked_mul(8)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?
    };
    let mut unwind_layouts = [0usize; MAX_LINK_INPUTS];
    let mut length = if has_unwind {
        if readonly_size == 0 {
            readonly_offset
        } else {
            align(base_length, 8)?
        }
    } else {
        base_length
    };
    let frame_header_offset = if frame_header_size == 0 {
        0
    } else {
        length = align(length, 4)?;
        let offset = length;
        length = length
            .checked_add(frame_header_size)
            .ok_or(LinkerError::OffsetOverflow)?;
        offset
    };
    let mut unwind_relocation_count = 0usize;
    for (index, data) in unwind.iter().enumerate() {
        length = align(length, 8)?;
        unwind_layouts[index] = length;
        length = length
            .checked_add(data.bytes.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        unwind_relocation_count = unwind_relocation_count
            .checked_add(data.relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if unwind_relocation_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for relocation in data.relocations {
            relocation
                .offset
                .checked_add(4)
                .filter(|end| *end <= data.bytes.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            validate_elf_fde_field(data.bytes, relocation.offset)?;
            if relocation.target_text_offset > inputs[index].text.len() {
                return Err(LinkerError::InvalidRelocationOffset);
            }
        }
    }
    let readonly_end = length;
    let has_writable = writable
        .iter()
        .any(|data| !data.initialized.is_empty() || data.zeroed_size != 0);
    let mut writable_initialized_layouts = [0usize; MAX_LINK_INPUTS];
    let mut writable_zeroed_layouts = [0usize; MAX_LINK_INPUTS];
    let writable_offset = if has_writable {
        align(readonly_end, PAGE)?
    } else {
        0
    };
    let mut writable_cursor = writable_offset;
    let mut writable_reference_count = 0usize;
    let mut writable_absolute_count = 0usize;
    for (index, data) in writable.iter().enumerate() {
        if data.initialized_alignment == 0
            || !data.initialized_alignment.is_power_of_two()
            || data.initialized_alignment > PAGE
            || data.zeroed_alignment == 0
            || !data.zeroed_alignment.is_power_of_two()
            || data.zeroed_alignment > PAGE
        {
            return Err(LinkerError::InvalidElf);
        }
        writable_cursor = align(writable_cursor, data.initialized_alignment.max(16))?;
        writable_initialized_layouts[index] = writable_cursor;
        writable_cursor = writable_cursor
            .checked_add(data.initialized.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        writable_reference_count = writable_reference_count
            .checked_add(data.references.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if writable_reference_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        writable_absolute_count = writable_absolute_count
            .checked_add(data.absolute_relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if writable_absolute_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for reference in data.references {
            reference
                .text_offset
                .checked_add(4)
                .filter(|end| *end <= inputs[index].text.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            match reference.target {
                ElfWritableTarget::Initialized(offset) if offset > data.initialized.len() => {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableTarget::Zeroed(offset) if offset > data.zeroed_size => {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableTarget::Initialized(_) | ElfWritableTarget::Zeroed(_) => {}
            }
        }
        for relocation in data.absolute_relocations {
            relocation
                .offset
                .checked_add(8)
                .filter(|end| *end <= data.initialized.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
            match relocation.target {
                ElfWritableAbsoluteTarget::Symbol(symbol) => validate_symbol(symbol)?,
                ElfWritableAbsoluteTarget::InputText(offset)
                    if offset > inputs[index].text.len() =>
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableAbsoluteTarget::ReadonlyData(offset)
                    if offset > inputs[index].readonly_data.len() =>
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableAbsoluteTarget::Initialized(offset)
                    if offset > data.initialized.len() =>
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableAbsoluteTarget::Zeroed(offset) if offset > data.zeroed_size => {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                ElfWritableAbsoluteTarget::InputText(_)
                | ElfWritableAbsoluteTarget::ReadonlyData(_)
                | ElfWritableAbsoluteTarget::Initialized(_)
                | ElfWritableAbsoluteTarget::Zeroed(_) => {}
            }
        }
    }
    let writable_file_end = writable_cursor;
    for (index, data) in writable.iter().enumerate() {
        writable_cursor = align(writable_cursor, data.zeroed_alignment.max(16))?;
        writable_zeroed_layouts[index] = writable_cursor;
        writable_cursor = writable_cursor
            .checked_add(data.zeroed_size)
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let writable_memory_end = writable_cursor;
    length = if has_writable {
        writable_file_end
    } else {
        readonly_end
    };
    if length > MAX_IMAGE_BYTES || writable_memory_end > MAX_IMAGE_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }
    let has_readonly_load = readonly_size != 0 || has_unwind;
    let program_count = 2
        + usize::from(has_readonly_load)
        + usize::from(frame_header_size != 0)
        + usize::from(has_writable);
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
    if has_readonly_load {
        write_elf_load_segment(
            &mut bytes,
            176,
            4,
            readonly_offset,
            IMAGE_BASE + readonly_offset,
            readonly_end
                .checked_sub(readonly_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
            readonly_end
                .checked_sub(readonly_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
        )?;
    }
    if frame_header_size != 0 {
        write_elf_program_segment(
            &mut bytes,
            232,
            0x6474_e550,
            4,
            frame_header_offset,
            IMAGE_BASE + frame_header_offset,
            frame_header_size,
            frame_header_size,
            4,
        )?;
    }
    if has_writable {
        let writable_program =
            64 + 56 * (2 + usize::from(has_readonly_load) + usize::from(frame_header_size != 0));
        write_elf_load_segment(
            &mut bytes,
            writable_program,
            6,
            writable_offset,
            IMAGE_BASE + writable_offset,
            writable_file_end
                .checked_sub(writable_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
            writable_memory_end
                .checked_sub(writable_offset)
                .ok_or(LinkerError::OffsetOverflow)?,
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
    for (index, data) in unwind.iter().enumerate() {
        copy_at(&mut bytes, unwind_layouts[index], data.bytes)?;
        for relocation in data.relocations {
            let place = unwind_layouts[index]
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = TEXT_OFFSET
                .checked_add(linked.layouts[index].text)
                .and_then(|target| target.checked_add(relocation.target_text_offset))
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement = i64::try_from(target)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(relocation.addend)
                .and_then(|target| target.checked_sub(i64::try_from(place).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement =
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?;
            bytes[place..place + 4].copy_from_slice(&displacement.to_le_bytes());
        }
    }
    if frame_header_size != 0 {
        bytes[frame_header_offset..frame_header_offset + 4].copy_from_slice(&[1, 0x1b, 3, 0x3b]);
        let first_frame = unwind_layouts
            .iter()
            .zip(unwind.iter())
            .find_map(|(layout, data)| (!data.bytes.is_empty()).then_some(*layout))
            .ok_or(LinkerError::InvalidElf)?;
        let frame_pointer = i64::try_from(first_frame)
            .map_err(|_| LinkerError::OffsetOverflow)?
            .checked_sub(
                i64::try_from(frame_header_offset + 4).map_err(|_| LinkerError::OffsetOverflow)?,
            )
            .ok_or(LinkerError::OffsetOverflow)?;
        patch_i32(
            &mut bytes,
            frame_header_offset + 4,
            i32::try_from(frame_pointer).map_err(|_| LinkerError::RelocationOverflow)?,
        )?;
        patch_u32(
            &mut bytes,
            frame_header_offset + 8,
            u32::try_from(frame_count).map_err(|_| LinkerError::OffsetOverflow)?,
        )?;
        let mut entries = [(0usize, 0usize); MAX_LINK_RELOCATIONS];
        let mut entry_count = 0usize;
        for (index, data) in unwind.iter().enumerate() {
            for relocation in data.relocations {
                let function = TEXT_OFFSET
                    .checked_add(linked.layouts[index].text)
                    .and_then(|target| target.checked_add(relocation.target_text_offset))
                    .ok_or(LinkerError::OffsetOverflow)?;
                let fde = unwind_layouts[index]
                    .checked_add(relocation.offset)
                    .and_then(|field| field.checked_sub(8))
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                let mut position = entry_count;
                while position != 0 && entries[position - 1].0 > function {
                    entries[position] = entries[position - 1];
                    position -= 1;
                }
                entries[position] = (function, fde);
                entry_count += 1;
            }
        }
        for (index, (function, fde)) in entries[..entry_count].iter().copied().enumerate() {
            let entry = frame_header_offset + 12 + index * 8;
            let function = i64::try_from(function)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_sub(
                    i64::try_from(frame_header_offset).map_err(|_| LinkerError::OffsetOverflow)?,
                )
                .ok_or(LinkerError::OffsetOverflow)?;
            let fde = i64::try_from(fde)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_sub(
                    i64::try_from(frame_header_offset).map_err(|_| LinkerError::OffsetOverflow)?,
                )
                .ok_or(LinkerError::OffsetOverflow)?;
            patch_i32(
                &mut bytes,
                entry,
                i32::try_from(function).map_err(|_| LinkerError::RelocationOverflow)?,
            )?;
            patch_i32(
                &mut bytes,
                entry + 4,
                i32::try_from(fde).map_err(|_| LinkerError::RelocationOverflow)?,
            )?;
        }
    }
    for (index, data) in writable.iter().enumerate() {
        copy_at(
            &mut bytes,
            writable_initialized_layouts[index],
            data.initialized,
        )?;
        for reference in data.references {
            let place = TEXT_OFFSET
                .checked_add(linked.layouts[index].text)
                .and_then(|place| place.checked_add(reference.text_offset))
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = match reference.target {
                ElfWritableTarget::Initialized(offset) => writable_initialized_layouts[index]
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                ElfWritableTarget::Zeroed(offset) => writable_zeroed_layouts[index]
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
            };
            let displacement = i64::try_from(target)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(reference.addend)
                .and_then(|target| target.checked_sub(i64::try_from(place).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            patch_i32(
                &mut bytes,
                place,
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?,
            )?;
        }
        for relocation in data.absolute_relocations {
            let output = writable_initialized_layouts[index]
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = match relocation.target {
                ElfWritableAbsoluteTarget::Symbol(symbol) => TEXT_OFFSET
                    .checked_add(resolve_symbol(inputs, &linked.layouts, symbol)?)
                    .ok_or(LinkerError::OffsetOverflow)?,
                ElfWritableAbsoluteTarget::InputText(offset) => TEXT_OFFSET
                    .checked_add(linked.layouts[index].text)
                    .and_then(|target| target.checked_add(offset))
                    .ok_or(LinkerError::OffsetOverflow)?,
                ElfWritableAbsoluteTarget::ReadonlyData(offset) => TEXT_OFFSET
                    .checked_add(linked.layouts[index].readonly)
                    .and_then(|target| target.checked_add(offset))
                    .ok_or(LinkerError::OffsetOverflow)?,
                ElfWritableAbsoluteTarget::Initialized(offset) => writable_initialized_layouts
                    [index]
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                ElfWritableAbsoluteTarget::Zeroed(offset) => writable_zeroed_layouts[index]
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
            };
            let target = i64::try_from(
                IMAGE_BASE
                    .checked_add(target)
                    .ok_or(LinkerError::OffsetOverflow)?,
            )
            .map_err(|_| LinkerError::OffsetOverflow)?
            .checked_add(relocation.addend)
            .ok_or(LinkerError::OffsetOverflow)?;
            patch_u64(
                &mut bytes,
                output,
                u64::try_from(target).map_err(|_| LinkerError::RelocationOverflow)?,
            )?;
        }
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
    write_elf_program_segment(
        output,
        offset,
        1,
        flags,
        file_offset,
        virtual_address,
        file_size,
        memory_size,
        0x1000,
    )
}

fn write_elf_program_segment<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    segment_type: u32,
    flags: u32,
    file_offset: usize,
    virtual_address: usize,
    file_size: usize,
    memory_size: usize,
    alignment: usize,
) -> Result<(), LinkerError> {
    patch_u32(output, offset, segment_type)?;
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
    patch_u64(
        output,
        offset + 48,
        u64::try_from(alignment).map_err(|_| LinkerError::OffsetOverflow)?,
    )
}

fn link_x86_64_static_aligned<const MAX_BYTES: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry_symbol: &str,
    section_alignment: usize,
) -> Result<LinkedImage<MAX_BYTES>, LinkerError> {
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_FRAGMENTS {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;

    // Pass 1: validate independent inputs and construct the global symbol set.
    let mut relocation_count = 0usize;
    for (index, input) in inputs.iter().enumerate() {
        validate_symbol(input.symbol)?;
        validate_definition_target(input, input.symbol_target)?;
        for (definition_index, definition) in input.additional_definitions.iter().enumerate() {
            validate_symbol(definition.symbol)?;
            validate_definition_target(input, definition.target)?;
            if definition_is_global(definition.target)
                && (definition_is_global(input.symbol_target) && definition.symbol == input.symbol
                    || input.additional_definitions[..definition_index]
                        .iter()
                        .any(|earlier| {
                            definition_is_global(earlier.target)
                                && earlier.symbol == definition.symbol
                        }))
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        relocation_count = relocation_count
            .checked_add(input.relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if relocation_count > MAX_LINK_TOTAL_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for definition in core::iter::once(LinkDefinition {
            symbol: input.symbol,
            target: input.symbol_target,
        })
        .chain(input.additional_definitions.iter().copied())
        .filter(|definition| definition_is_global(definition.target))
        {
            if inputs[..index]
                .iter()
                .any(|earlier| input_definition_target(earlier, definition.symbol).is_some())
            {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        for relocation in input.relocations {
            match relocation.target {
                LinkRelocationTarget::Symbol(symbol)
                | LinkRelocationTarget::GotPcRelativeSymbol(symbol)
                | LinkRelocationTarget::RequiredSymbol(symbol)
                | LinkRelocationTarget::LocalSymbol(symbol)
                | LinkRelocationTarget::PeWritableSymbol(symbol) => validate_symbol(symbol)?,
                LinkRelocationTarget::PeImportAddress { library, symbol } => {
                    validate_pe_import_library(library)?;
                    validate_symbol(symbol)?;
                }
                LinkRelocationTarget::PeTlsSection { identity, .. }
                    if identity.object == 0 || identity.section == 0 =>
                {
                    return Err(LinkerError::InvalidCoff);
                }
                LinkRelocationTarget::PeTlsSection { .. } => {}
                LinkRelocationTarget::InputText(offset) if offset > input.text.len() => {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                LinkRelocationTarget::InputText(_) => {}
                LinkRelocationTarget::ReadonlyData(offset)
                | LinkRelocationTarget::GotPcRelativeReadonlyData(offset)
                    if offset > input.readonly_data.len() =>
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                LinkRelocationTarget::ReadonlyData(_)
                | LinkRelocationTarget::GotPcRelativeReadonlyData(_) => {}
                LinkRelocationTarget::CoffSection { identity, .. }
                    if identity.object == 0 || identity.section == 0 =>
                {
                    return Err(LinkerError::InvalidCoff);
                }
                LinkRelocationTarget::CoffSection { .. } => {}
            }
            if !matches!(
                relocation.target,
                LinkRelocationTarget::RequiredSymbol(_)
                    | LinkRelocationTarget::PeWritableSymbol(_)
            ) {
                relocation
                    .offset
                    .checked_add(4)
                    .filter(|end| *end <= input.text.len())
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
            }
        }
    }

    // Pass 2: freeze layout before copying bytes, following a text-first,
    // read-only-data-second policy. The fixed arrays keep all bounds explicit.
    let mut layouts = [InputLayout {
        text: 0,
        readonly: 0,
    }; MAX_LINK_FRAGMENTS];
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
            match relocation.target {
                LinkRelocationTarget::RequiredSymbol(symbol) => {
                    resolve_symbol(inputs, &layouts, symbol)?;
                    continue;
                }
                LinkRelocationTarget::PeWritableSymbol(_)
                | LinkRelocationTarget::PeImportAddress { .. }
                | LinkRelocationTarget::PeTlsSection { .. } => continue,
                _ => {}
            }
            let place = layout
                .text
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = match relocation.target {
                LinkRelocationTarget::Symbol(symbol)
                | LinkRelocationTarget::GotPcRelativeSymbol(symbol)
                | LinkRelocationTarget::LocalSymbol(symbol) => {
                    resolve_symbol(inputs, &layouts, symbol)?
                }
                LinkRelocationTarget::RequiredSymbol(_) => unreachable!(),
                LinkRelocationTarget::PeWritableSymbol(_) => unreachable!(),
                LinkRelocationTarget::PeImportAddress { .. } => unreachable!(),
                LinkRelocationTarget::PeTlsSection { .. } => unreachable!(),
                LinkRelocationTarget::InputText(offset) => layout
                    .text
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                LinkRelocationTarget::ReadonlyData(offset) => layout
                    .readonly
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                LinkRelocationTarget::GotPcRelativeReadonlyData(offset) => layout
                    .readonly
                    .checked_add(offset)
                    .ok_or(LinkerError::OffsetOverflow)?,
                LinkRelocationTarget::CoffSection { identity, offset } => {
                    resolve_coff_section(inputs, &layouts, identity, offset)?
                }
            };
            let displacement = i64::try_from(target)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(relocation.addend)
                .and_then(|value| value.checked_sub(i64::try_from(place).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement =
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?;
            if matches!(
                relocation.target,
                LinkRelocationTarget::GotPcRelativeSymbol(_)
            ) {
                let prefix = place
                    .checked_sub(2)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                let opcode = *output
                    .get(prefix + 1)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                output[prefix] = 0x90;
                output[prefix + 1] = match opcode {
                    0x15 => 0xe8,
                    0x25 => 0xe9,
                    _ => return Err(LinkerError::UnsupportedElf),
                };
            }
            if matches!(
                relocation.target,
                LinkRelocationTarget::GotPcRelativeReadonlyData(_)
            ) {
                let prefix = place
                    .checked_sub(3)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                let instruction = output
                    .get(prefix..place)
                    .ok_or(LinkerError::InvalidRelocationOffset)?;
                if instruction[0] != 0x48 || instruction[1] != 0x8b || instruction[2] & 0xc7 != 0x05
                {
                    return Err(LinkerError::UnsupportedElf);
                }
                output[prefix + 1] = 0x8d;
            }
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

fn write_pe_section(
    output: &mut [u8],
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

fn patch_u16(
    output: &mut [u8],
    offset: usize,
    value: u16,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 2)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_u32(
    output: &mut [u8],
    offset: usize,
    value: u32,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_i32(
    output: &mut [u8],
    offset: usize,
    value: i32,
) -> Result<(), LinkerError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_u64(
    output: &mut [u8],
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

fn validate_definition_target(
    input: &LinkInput<'_, '_, '_>,
    target: LinkDefinitionTarget,
) -> Result<(), LinkerError> {
    let valid = match target {
        LinkDefinitionTarget::Text(offset) => offset <= input.text.len(),
        LinkDefinitionTarget::ReadonlyData(offset) => offset <= input.readonly_data.len(),
        LinkDefinitionTarget::CoffTextSection { identity, offset } => {
            identity.object != 0 && identity.section != 0 && offset <= input.text.len()
        }
        LinkDefinitionTarget::CoffSection { identity, offset } => {
            identity.object != 0 && identity.section != 0 && offset <= input.readonly_data.len()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(LinkerError::InvalidRelocationOffset)
    }
}

fn resolve_symbol(
    inputs: &[LinkInput<'_, '_, '_>],
    layouts: &[InputLayout; MAX_LINK_FRAGMENTS],
    symbol: &str,
) -> Result<usize, LinkerError> {
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        if let Some(target) = input_definition_target(input, symbol) {
            return match target {
                LinkDefinitionTarget::Text(offset) => layout.text.checked_add(offset),
                LinkDefinitionTarget::ReadonlyData(offset) => layout.readonly.checked_add(offset),
                LinkDefinitionTarget::CoffTextSection { .. } => None,
                LinkDefinitionTarget::CoffSection { .. } => None,
            }
            .ok_or(LinkerError::OffsetOverflow);
        }
    }
    Err(LinkerError::UndefinedSymbol)
}

fn resolve_coff_section(
    inputs: &[LinkInput<'_, '_, '_>],
    layouts: &[InputLayout; MAX_LINK_FRAGMENTS],
    identity: CoffSectionIdentity,
    offset: usize,
) -> Result<usize, LinkerError> {
    let mut resolved = None;
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        let definitions = core::iter::once(input.symbol_target).chain(
            input
                .additional_definitions
                .iter()
                .map(|definition| definition.target),
        );
        for definition in definitions {
            let (candidate, base, section_base, section_size) = match definition {
                LinkDefinitionTarget::CoffTextSection { identity, offset } => {
                    (identity, offset, layout.text, input.text.len())
                }
                LinkDefinitionTarget::CoffSection { identity, offset } => {
                    (identity, offset, layout.readonly, input.readonly_data.len())
                }
                _ => continue,
            };
            if candidate == identity {
                if resolved.is_some()
                    || base
                        .checked_add(offset)
                        .filter(|end| *end <= section_size)
                        .is_none()
                {
                    return Err(LinkerError::InvalidRelocationOffset);
                }
                resolved = section_base
                    .checked_add(base)
                    .and_then(|target| target.checked_add(offset));
            }
        }
    }
    resolved.ok_or(LinkerError::UndefinedSymbol)
}

fn resolve_readonly_symbol(
    inputs: &[LinkInput<'_, '_, '_>],
    layouts: &[InputLayout; MAX_LINK_FRAGMENTS],
    linked_readonly_offset: usize,
    readonly_rva: usize,
    owner_symbol: &str,
    data_offset: usize,
) -> Result<usize, LinkerError> {
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        if input_definition_target(input, owner_symbol).is_some() {
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

fn copy_at(
    output: &mut [u8],
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

    fn append_thin_archive_member(archive: &mut std::vec::Vec<u8>, name: &str, size: usize) {
        let mut header = [b' '; 60];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = std::format!("{size}");
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        archive.extend_from_slice(&header);
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

    fn coff_with_tls_secrel_relocation() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 158];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&2u16.to_le_bytes());
        object[8..12].copy_from_slice(&118u32.to_le_bytes());
        object[12..16].copy_from_slice(&2u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&4u32.to_le_bytes());
        object[40..44].copy_from_slice(&100u32.to_le_bytes());
        object[44..48].copy_from_slice(&108u32.to_le_bytes());
        object[52..54].copy_from_slice(&1u16.to_le_bytes());
        object[56..60].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        object[60..66].copy_from_slice(b".tls$a");
        object[76..80].copy_from_slice(&4u32.to_le_bytes());
        object[80..84].copy_from_slice(&104u32.to_le_bytes());
        object[96..100].copy_from_slice(&0xc000_0040u32.to_le_bytes());

        object[108..112].copy_from_slice(&0u32.to_le_bytes());
        object[112..116].copy_from_slice(&1u32.to_le_bytes());
        object[116..118].copy_from_slice(&11u16.to_le_bytes());

        object[118..123].copy_from_slice(b"entry");
        object[130..132].copy_from_slice(&1i16.to_le_bytes());
        object[134] = 2;
        object[136..143].copy_from_slice(b"TLS_VAR");
        object[148..150].copy_from_slice(&2i16.to_le_bytes());
        object[152] = 2;
        object[154..158].copy_from_slice(&4u32.to_le_bytes());
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

    fn two_fragment_coff_with_discardable_debug() -> std::vec::Vec<u8> {
        let original = two_fragment_coff_with_removed_metadata();
        let mut object = std::vec![0u8; original.len() + 14];
        object[..157].copy_from_slice(&original[..157]);
        object[171..].copy_from_slice(&original[157..]);
        object[8..12].copy_from_slice(&171u32.to_le_bytes());

        object[100..140].fill(0);
        object[100..106].copy_from_slice(b".debug");
        object[116..120].copy_from_slice(&4u32.to_le_bytes());
        object[120..124].copy_from_slice(&157u32.to_le_bytes());
        object[124..128].copy_from_slice(&161u32.to_le_bytes());
        object[132..134].copy_from_slice(&1u16.to_le_bytes());
        object[136..140].copy_from_slice(&0x4230_0040u32.to_le_bytes());
        object[157..161].copy_from_slice(&[1, 2, 3, 4]);
        object[165..169].copy_from_slice(&0u32.to_le_bytes());
        object[169..171].copy_from_slice(&11u16.to_le_bytes());
        object
    }

    fn two_fragment_coff_with_associative_readonly() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 368];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&4u16.to_le_bytes());
        object[8..12].copy_from_slice(&184u32.to_le_bytes());
        object[12..16].copy_from_slice(&10u32.to_le_bytes());
        for (section, (name, offset)) in [
            (b".text$a".as_slice(), 180u32),
            (b".rdata$a".as_slice(), 181),
            (b".text$b".as_slice(), 182),
            (b".rdata$b".as_slice(), 183),
        ]
        .into_iter()
        .enumerate()
        {
            let header = 20 + section * 40;
            object[header..header + name.len()].copy_from_slice(name);
            object[header + 16..header + 20].copy_from_slice(&1u32.to_le_bytes());
            object[header + 20..header + 24].copy_from_slice(&offset.to_le_bytes());
            object[header + 36..header + 40].copy_from_slice(&0x4000_1000u32.to_le_bytes());
        }
        object[180..184].copy_from_slice(&[0xc3, b'A', 0xc3, b'B']);

        for (symbol_index, section, selection, parent) in [
            (0usize, 1i16, 2u8, 0u16),
            (3, 2, 5, 1),
            (5, 3, 2, 0),
            (8, 4, 5, 3),
        ] {
            let symbol = 184 + symbol_index * 18;
            object[symbol + 12..symbol + 14].copy_from_slice(&section.to_le_bytes());
            object[symbol + 16] = 3;
            object[symbol + 17] = 1;
            object[symbol + 18 + 12..symbol + 18 + 14].copy_from_slice(&parent.to_le_bytes());
            object[symbol + 18 + 14] = selection;
        }
        for (symbol_index, name, section) in [
            (2usize, b"entry".as_slice(), 1i16),
            (7, b"helper".as_slice(), 3),
        ] {
            let symbol = 184 + symbol_index * 18;
            object[symbol..symbol + name.len()].copy_from_slice(name);
            object[symbol + 12..symbol + 14].copy_from_slice(&section.to_le_bytes());
            object[symbol + 16] = 2;
        }
        object[364..368].copy_from_slice(&4u32.to_le_bytes());
        object
    }

    fn two_fragment_coff_with_associative_readonly_relocations() -> std::vec::Vec<u8> {
        let original = two_fragment_coff_with_associative_readonly();
        let mut object = std::vec![0u8; 402];
        object[..180].copy_from_slice(&original[..180]);
        object[8..12].copy_from_slice(&218u32.to_le_bytes());
        for (section, (size, raw, relocations, count)) in [
            (1usize, (8u32, 181u32, 198u32, 1u16)),
            (2, (1, 189, 0, 0)),
            (3, (8, 190, 208, 1)),
        ] {
            let header = 20 + section * 40;
            object[header + 16..header + 20].copy_from_slice(&size.to_le_bytes());
            object[header + 20..header + 24].copy_from_slice(&raw.to_le_bytes());
            object[header + 24..header + 28].copy_from_slice(&relocations.to_le_bytes());
            object[header + 32..header + 34].copy_from_slice(&count.to_le_bytes());
        }
        object[180] = 0xc3;
        object[181..189].copy_from_slice(&3i64.to_le_bytes());
        object[189] = 0xc3;
        object[190..198].copy_from_slice(&(-2i64).to_le_bytes());
        for (record, target) in [(198usize, 7u32), (208, 2)] {
            object[record + 4..record + 8].copy_from_slice(&target.to_le_bytes());
            object[record + 8..record + 10].copy_from_slice(&1u16.to_le_bytes());
        }
        object[218..402].copy_from_slice(&original[184..368]);
        object
    }

    fn coff_with_standalone_readonly_comdat() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 227];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&2u16.to_le_bytes());
        object[8..12].copy_from_slice(&115u32.to_le_bytes());
        object[12..16].copy_from_slice(&6u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&4u32.to_le_bytes());
        object[40..44].copy_from_slice(&100u32.to_le_bytes());
        object[44..48].copy_from_slice(&105u32.to_le_bytes());
        object[52..54].copy_from_slice(&1u16.to_le_bytes());
        object[56..60].copy_from_slice(&0x6050_1020u32.to_le_bytes());
        object[60..68].copy_from_slice(b".rdata$a");
        object[76..80].copy_from_slice(&1u32.to_le_bytes());
        object[80..84].copy_from_slice(&104u32.to_le_bytes());
        object[96..100].copy_from_slice(&0x4030_1040u32.to_le_bytes());
        object[104] = b'R';
        object[105..109].copy_from_slice(&0u32.to_le_bytes());
        object[109..113].copy_from_slice(&5u32.to_le_bytes());
        object[113..115].copy_from_slice(&4u16.to_le_bytes());

        for (symbol_index, section) in [(0usize, 1i16), (3, 2)] {
            let symbol = 115 + symbol_index * 18;
            object[symbol + 12..symbol + 14].copy_from_slice(&section.to_le_bytes());
            object[symbol + 16] = 3;
            object[symbol + 17] = 1;
            object[symbol + 18 + 14] = 2;
        }
        for (symbol_index, name, section) in [
            (2usize, b"entry".as_slice(), 1i16),
            (5, b"literal".as_slice(), 2),
        ] {
            let symbol = 115 + symbol_index * 18;
            object[symbol..symbol + name.len()].copy_from_slice(name);
            object[symbol + 12..symbol + 14].copy_from_slice(&section.to_le_bytes());
            object[symbol + 16] = 2;
        }
        object[223..227].copy_from_slice(&4u32.to_le_bytes());
        object
    }

    fn coff_with_multiple_standalone_readonly_relocations() -> std::vec::Vec<u8> {
        let original = coff_with_standalone_readonly_comdat();
        let mut object = std::vec![0u8; 262];
        object[..100].copy_from_slice(&original[..100]);
        object[8..12].copy_from_slice(&150u32.to_le_bytes());
        object[44..48].copy_from_slice(&140u32.to_le_bytes());
        object[76..80].copy_from_slice(&16u32.to_le_bytes());
        object[84..88].copy_from_slice(&120u32.to_le_bytes());
        object[92..94].copy_from_slice(&2u16.to_le_bytes());
        object[104..112].copy_from_slice(&5i64.to_le_bytes());
        object[112..120].copy_from_slice(&(-4i64).to_le_bytes());
        for (record, (field, target)) in [(0u32, 2u32), (8, 5)].into_iter().enumerate() {
            let offset = 120 + record * 10;
            object[offset..offset + 4].copy_from_slice(&field.to_le_bytes());
            object[offset + 4..offset + 8].copy_from_slice(&target.to_le_bytes());
            object[offset + 8..offset + 10]
                .copy_from_slice(&(if record == 0 { 3u16 } else { 1 }).to_le_bytes());
        }
        object[140..150].copy_from_slice(&original[105..115]);
        object[150..262].copy_from_slice(&original[115..227]);
        object
    }

    fn coff_with_one_runtime_function() -> std::vec::Vec<u8> {
        let mut object = std::vec![0u8; 317];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&3u16.to_le_bytes());
        object[8..12].copy_from_slice(&187u32.to_le_bytes());
        object[12..16].copy_from_slice(&7u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$a");
        object[36..40].copy_from_slice(&1u32.to_le_bytes());
        object[40..44].copy_from_slice(&140u32.to_le_bytes());
        object[56..60].copy_from_slice(&0x6050_1020u32.to_le_bytes());
        object[60..68].copy_from_slice(b".xdata$a");
        object[76..80].copy_from_slice(&4u32.to_le_bytes());
        object[80..84].copy_from_slice(&141u32.to_le_bytes());
        object[96..100].copy_from_slice(&0x4030_1040u32.to_le_bytes());
        object[100..108].copy_from_slice(b".pdata$a");
        object[116..120].copy_from_slice(&12u32.to_le_bytes());
        object[120..124].copy_from_slice(&145u32.to_le_bytes());
        object[124..128].copy_from_slice(&157u32.to_le_bytes());
        object[132..134].copy_from_slice(&3u16.to_le_bytes());
        object[136..140].copy_from_slice(&0x4030_1040u32.to_le_bytes());

        object[140] = 0xc3;
        object[141..145].copy_from_slice(&[1, 2, 3, 4]);
        object[149..153].copy_from_slice(&1u32.to_le_bytes());
        for (record, field) in [0u32, 4, 8].into_iter().enumerate() {
            let offset = 157 + record * 10;
            object[offset..offset + 4].copy_from_slice(&field.to_le_bytes());
            object[offset + 4..offset + 8]
                .copy_from_slice(&(if record == 2 { 3u32 } else { 0u32 }).to_le_bytes());
            object[offset + 8..offset + 10].copy_from_slice(&3u16.to_le_bytes());
        }

        object[187..194].copy_from_slice(b".text$a");
        object[199..201].copy_from_slice(&1i16.to_le_bytes());
        object[203] = 3;
        object[204] = 1;
        object[219] = 2;
        object[223..228].copy_from_slice(b"entry");
        object[235..237].copy_from_slice(&1i16.to_le_bytes());
        object[239] = 2;
        object[241..249].copy_from_slice(b".xdata$a");
        object[253..255].copy_from_slice(&2i16.to_le_bytes());
        object[257] = 3;
        object[258] = 1;
        object[271..273].copy_from_slice(&1u16.to_le_bytes());
        object[273] = 5;
        object[277..285].copy_from_slice(b".pdata$a");
        object[289..291].copy_from_slice(&3i16.to_le_bytes());
        object[293] = 3;
        object[294] = 1;
        object[307..309].copy_from_slice(&1u16.to_le_bytes());
        object[309] = 5;
        object[313..317].copy_from_slice(&4u32.to_le_bytes());
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

    fn coff_with_any_writable_comdat() -> std::vec::Vec<u8> {
        let mut object = coff_with_readonly_and_writable_data();
        object.resize(239, 0);
        object.copy_within(199..203, 235);
        object[12..16].copy_from_slice(&4u32.to_le_bytes());
        object[199..206].copy_from_slice(b".data$a");
        object[211..213].copy_from_slice(&3i16.to_le_bytes());
        object[215] = 3;
        object[216] = 1;
        object[217..221].copy_from_slice(&8u32.to_le_bytes());
        object[221..223].copy_from_slice(&1u16.to_le_bytes());
        object[231] = 2;
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
                bytes: b"one",
                external: false,
            }
        );
        assert_eq!(
            members.members()[1],
            ArchiveMember {
                name: "long-object-name.o",
                bytes: b"two2",
                external: false,
            }
        );
        assert_eq!(
            members.members()[2],
            ArchiveMember {
                name: "bsd-name.o",
                bytes: b"three",
                external: false,
            }
        );

        let mut coff_archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut coff_archive, "//", b"coff-long-name.o\0");
        append_archive_member(&mut coff_archive, "/0", b"object");
        assert_eq!(
            decode_unix_archive(&coff_archive).unwrap().members(),
            &[ArchiveMember {
                name: "coff-long-name.o",
                bytes: b"object",
                external: false,
            }]
        );
    }

    #[test]
    fn decodes_validated_gnu_archive_symbol_indexes() {
        let mut archive = b"!<arch>\n".to_vec();
        let mut index = std::vec![0, 0, 0, 1, 0, 0, 0, 82];
        index.extend_from_slice(b"entry\0");
        append_archive_member(&mut archive, "/", &index);
        append_archive_member(&mut archive, "entry.o/", b"object");
        let mut bsd_index = b"__.SYMDEF SORTED".to_vec();
        bsd_index.extend_from_slice(b"bsd-index");
        append_archive_member(&mut archive, "#1/16", &bsd_index);

        let members = decode_unix_archive(&archive).unwrap();
        assert_eq!(
            members.members(),
            &[ArchiveMember {
                name: "entry.o",
                bytes: b"object",
                external: false,
            }]
        );
        assert_eq!(
            members.symbols(),
            &[ArchiveSymbol {
                symbol: "entry",
                member_index: 0
            }]
        );
        assert_eq!(
            members.member_for_symbol("entry"),
            Some(&members.members()[0])
        );
        assert_eq!(members.member_for_symbol("missing"), None);

        let mut wide_archive = b"!<arch>\n".to_vec();
        let mut wide = std::vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 90];
        wide.extend_from_slice(b"entry\0");
        append_archive_member(&mut wide_archive, "/SYM64/", &wide);
        append_archive_member(&mut wide_archive, "entry.o/", b"object");
        assert_eq!(
            decode_unix_archive(&wide_archive).unwrap().symbols(),
            members.symbols()
        );

        let mut padded_archive = b"!<arch>\n".to_vec();
        let mut padded = std::vec![0, 0, 0, 1, 0, 0, 0, 82];
        padded.extend_from_slice(b"even\0\0");
        append_archive_member(&mut padded_archive, "/", &padded);
        append_archive_member(&mut padded_archive, "even.o/", b"object");
        assert_eq!(
            decode_unix_archive(&padded_archive).unwrap().symbols(),
            &[ArchiveSymbol {
                symbol: "even",
                member_index: 0
            }]
        );

        let mut empty_padded_archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut empty_padded_archive, "/", &[0; 8]);
        append_archive_member(&mut empty_padded_archive, "empty.o/", b"object");
        assert!(
            decode_unix_archive(&empty_padded_archive)
                .unwrap()
                .symbols()
                .is_empty()
        );

        let mut excessive_padding_archive = b"!<arch>\n".to_vec();
        append_archive_member(&mut excessive_padding_archive, "/", &[0; 12]);
        append_archive_member(&mut excessive_padding_archive, "empty.o/", b"object");
        assert_eq!(
            decode_unix_archive(&excessive_padding_archive),
            Err(LinkerError::InvalidArchive)
        );
    }

    #[test]
    fn validates_redundant_coff_archive_linker_members() {
        let mut archive = b"!<arch>\n".to_vec();
        let mut first = std::vec![0, 0, 0, 1, 0, 0, 0, 162];
        first.extend_from_slice(b"entry\0");
        append_archive_member(&mut archive, "/", &first);
        let mut second = std::vec::Vec::new();
        second.extend_from_slice(&1u32.to_le_bytes());
        second.extend_from_slice(&162u32.to_le_bytes());
        second.extend_from_slice(&1u32.to_le_bytes());
        second.extend_from_slice(&1u16.to_le_bytes());
        second.extend_from_slice(b"entry\0");
        append_archive_member(&mut archive, "/", &second);
        append_archive_member(&mut archive, "entry.o/", b"object");

        let decoded = decode_unix_archive(&archive).unwrap();
        assert_eq!(decoded.members().len(), 1);
        assert_eq!(decoded.member_for_symbol("entry"), Some(&decoded.members()[0]));

        let mut padded_archive = b"!<arch>\n".to_vec();
        let mut padded_first = std::vec![0, 0, 0, 1, 0, 0, 0, 164];
        padded_first.extend_from_slice(b"entry\0");
        append_archive_member(&mut padded_archive, "/", &padded_first);
        let mut padded_second = std::vec::Vec::new();
        padded_second.extend_from_slice(&1u32.to_le_bytes());
        padded_second.extend_from_slice(&164u32.to_le_bytes());
        padded_second.extend_from_slice(&1u32.to_le_bytes());
        padded_second.extend_from_slice(&1u16.to_le_bytes());
        padded_second.extend_from_slice(b"entry\0\0");
        append_archive_member(&mut padded_archive, "/", &padded_second);
        append_archive_member(&mut padded_archive, "entry.o/", b"object");
        assert_eq!(
            decode_unix_archive(&padded_archive)
                .unwrap()
                .member_for_symbol("entry")
                .unwrap()
                .name,
            "entry.o"
        );

        let second_payload = 8 + 60 + first.len() + 60;
        for offset in [0usize, 8, 12] {
            let mut malformed = archive.clone();
            malformed[second_payload + offset] = 0;
            assert_eq!(
                decode_unix_archive(&malformed),
                Err(LinkerError::InvalidArchive)
            );
        }
        let mut missing_name = archive;
        *missing_name.get_mut(second_payload + 19).unwrap() = b'x';
        assert_eq!(
            decode_unix_archive(&missing_name),
            Err(LinkerError::InvalidArchive)
        );
    }

    #[test]
    fn rejects_untrusted_gnu_archive_index_offsets_and_names() {
        let mut bad_offset = b"!<arch>\n".to_vec();
        let mut index = std::vec![0, 0, 0, 1, 0, 0, 0, 81];
        index.extend_from_slice(b"entry\0");
        append_archive_member(&mut bad_offset, "/", &index);
        append_archive_member(&mut bad_offset, "entry.o/", b"object");
        assert_eq!(
            decode_unix_archive(&bad_offset),
            Err(LinkerError::InvalidArchive)
        );

        let mut missing_nul = b"!<arch>\n".to_vec();
        append_archive_member(&mut missing_nul, "/", &[0, 0, 0, 1, 0, 0, 0, 78, b'e']);
        append_archive_member(&mut missing_nul, "entry.o/", b"object");
        assert_eq!(
            decode_unix_archive(&missing_nul),
            Err(LinkerError::InvalidArchive)
        );
    }

    #[test]
    fn rejects_truncated_and_unresolved_archive_members() {
        assert!(
            decode_unix_archive(b"!<thin>\n")
                .unwrap()
                .members()
                .is_empty()
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
    fn decodes_bounded_gnu_thin_archive_member_paths() {
        let mut archive = b"!<thin>\n".to_vec();
        append_archive_member(&mut archive, "//", b"sub/entry.o/\nhelper.o/\n");
        append_thin_archive_member(&mut archive, "/0", 1234);
        append_thin_archive_member(&mut archive, "/13", 5678);
        let members = decode_unix_archive(&archive).unwrap();
        assert_eq!(
            members.members(),
            &[
                ArchiveMember {
                    name: "sub/entry.o",
                    bytes: &[],
                    external: true,
                },
                ArchiveMember {
                    name: "helper.o",
                    bytes: &[],
                    external: true,
                },
            ]
        );

        let mut bsd = b"!<thin>\n".to_vec();
        append_thin_archive_member(&mut bsd, "#1/4", 4);
        assert_eq!(
            decode_unix_archive(&bsd),
            Err(LinkerError::UnsupportedArchive)
        );

        let mut traversal = b"!<thin>\n".to_vec();
        append_thin_archive_member(&mut traversal, "../escape.o/", 8);
        assert_eq!(
            decode_unix_archive(&traversal),
            Err(LinkerError::InvalidArchive)
        );
        let mut absolute = b"!<thin>\n".to_vec();
        append_thin_archive_member(&mut absolute, "/tmp/x.o/", 8);
        assert_eq!(
            decode_unix_archive(&absolute),
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
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &entry_relocation,
            },
            LinkInput {
                symbol: "unused",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "middle",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0; 4],
                readonly_data: &[],
                relocations: &middle_relocation,
            },
            LinkInput {
                symbol: "leaf",
                symbol_target: LinkDefinitionTarget::Text(0),
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
    fn selects_archive_members_required_by_non_text_relocations() {
        let required = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::RequiredSymbol("helper"),
            addend: 0,
        }];
        let inputs = [
            LinkInput {
                symbol: "entry",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &required,
            },
            LinkInput {
                symbol: "helper",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
        ];
        let selection = select_static_link_inputs(&inputs, &[false, true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0, 1]);
        assert!(link_x86_64_static::<64>(&inputs, "entry").is_ok());
    }

    #[test]
    fn selects_and_resolves_readonly_only_archive_definitions() {
        let required = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::RequiredSymbol("external_data"),
            addend: 0,
        }];
        let inputs = [
            LinkInput {
                symbol: "entry",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &required,
            },
            LinkInput {
                symbol: "external_data",
                symbol_target: LinkDefinitionTarget::ReadonlyData(0),
                additional_definitions: &[],
                text: &[],
                readonly_data: &[42],
                relocations: &[],
            },
        ];
        let selection = select_static_link_inputs(&inputs, &[false, true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0, 1]);
        let linked = link_x86_64_static::<64>(&inputs, "entry").unwrap();
        assert_eq!(linked.bytes()[16], 42);

        let invalid = LinkInput {
            symbol_target: LinkDefinitionTarget::ReadonlyData(2),
            ..inputs[1]
        };
        assert_eq!(
            link_x86_64_static::<64>(&[inputs[0], invalid], "entry"),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn selects_an_archive_entry_and_ignores_later_duplicate_members() {
        let inputs = [
            LinkInput {
                symbol: "entry",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "entry",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xcc],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "unused",
                symbol_target: LinkDefinitionTarget::Text(0),
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
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &[],
        };
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
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
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0, 0, 0, 0],
            readonly_data: &[],
            relocations: &call_helper,
        };
        let helper = LinkInput {
            symbol: "helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let unwind_fragment = LinkInput {
            symbol: "helper.unwind",
            symbol_target: LinkDefinitionTarget::Text(0),
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
    fn ordered_archive_selection_pulls_only_exact_typed_section_fragment() {
        let wanted_identity = CoffSectionIdentity::new(2, 7).unwrap();
        let unrelated_identity = CoffSectionIdentity::new(2, 9).unwrap();
        let exact_reference = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::CoffSection {
                identity: wanted_identity,
                offset: 0,
            },
            addend: -4,
        }];
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &exact_reference,
        };
        let wanted = LinkInput {
            symbol: ".rdata$wanted",
            symbol_target: LinkDefinitionTarget::CoffSection {
                identity: wanted_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[],
            readonly_data: b"wanted",
            relocations: &[],
        };
        let unrelated = LinkInput {
            symbol: ".rdata$unrelated",
            symbol_target: LinkDefinitionTarget::CoffSection {
                identity: unrelated_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[],
            readonly_data: b"unrelated",
            relocations: &[],
        };

        let selection = select_ordered_static_link_members(
            &[entry, wanted, unrelated],
            &[0, 1, 1],
            &[0, 5, 5],
            "entry",
        )
        .unwrap();
        assert_eq!(selection.indices(), &[0, 1]);
    }

    #[test]
    fn ordered_archive_selection_separates_fragment_and_source_input_bounds() {
        let fragment = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let inputs = [fragment; MAX_LINK_INPUTS + 1];
        let groups = [1; MAX_LINK_INPUTS + 1];
        let members = [7; MAX_LINK_INPUTS + 1];

        let selection =
            select_ordered_static_link_members(&inputs, &groups, &members, "entry").unwrap();
        assert_eq!(selection.indices().len(), MAX_LINK_INPUTS + 1);
    }

    #[test]
    fn ordered_archive_selection_separates_object_and_aggregate_fragment_bounds() {
        let fragment = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let inputs = [fragment; MAX_COFF_SECTIONS + 1];
        let groups = [1; MAX_COFF_SECTIONS + 1];
        let members = [7; MAX_COFF_SECTIONS + 1];

        let selection =
            select_ordered_static_link_members(&inputs, &groups, &members, "entry").unwrap();
        assert_eq!(selection.indices().len(), MAX_COFF_SECTIONS + 1);
    }

    #[test]
    fn ordered_archive_member_identity_fails_closed_outside_archives() {
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
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
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"A",
                relocations: &[to_helper],
            },
            LinkInput {
                symbol: "helper",
                symbol_target: LinkDefinitionTarget::Text(0),
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
    fn resolves_exact_non_global_coff_section_identities() {
        assert_eq!(
            CoffSectionIdentity::new(0, 1),
            Err(LinkerError::InvalidCoff)
        );
        assert_eq!(
            CoffSectionIdentity::new(1, 0),
            Err(LinkerError::InvalidCoff)
        );
        let first_identity = CoffSectionIdentity::new(1, 7).unwrap();
        let second_identity = CoffSectionIdentity::new(2, 7).unwrap();
        let relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::CoffSection {
                identity: second_identity,
                offset: 0,
            },
            addend: -4,
        }];
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &relocation,
        };
        let first = LinkInput {
            symbol: ".rdata",
            symbol_target: LinkDefinitionTarget::CoffSection {
                identity: first_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[],
            readonly_data: b"A",
            relocations: &[],
        };
        let second = LinkInput {
            symbol: ".rdata",
            symbol_target: LinkDefinitionTarget::CoffSection {
                identity: second_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[],
            readonly_data: b"B",
            relocations: &[],
        };
        let linked = link_x86_64_static::<64>(&[entry, first, second], "entry").unwrap();
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            28
        );
        assert_eq!(linked.bytes()[32], b'B');

        let selection =
            select_static_link_inputs(&[entry, first], &[false, true], "entry").unwrap();
        assert_eq!(selection.indices(), &[0]);
    }

    #[test]
    fn links_same_named_local_text_section_identities_without_global_collisions() {
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let first = LinkInput {
            symbol: ".text$local",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity: CoffSectionIdentity::new(1, 7).unwrap(),
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let second = LinkInput {
            symbol: ".text$local",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity: CoffSectionIdentity::new(2, 7).unwrap(),
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xcc, 0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let linked = link_x86_64_static::<64>(&[entry, first, second], "entry").unwrap();
        assert_eq!(linked.bytes()[16], 0xc3);
        assert_eq!(&linked.bytes()[32..34], &[0xcc, 0xc3]);
    }

    #[test]
    fn resolves_multiple_definitions_at_checked_text_offsets() {
        let definitions = [LinkDefinition {
            symbol: "secondary",
            target: LinkDefinitionTarget::Text(1),
        }];
        let input = LinkInput {
            symbol: "primary",
            symbol_target: LinkDefinitionTarget::Text(0),
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
                target: LinkDefinitionTarget::Text(8),
            }],
            ..input
        };
        assert_eq!(
            link_x86_64_static::<32>(&[invalid], "primary"),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn relaxes_only_validated_static_gotpcrel_call_and_jump_shapes() {
        let relocation = LinkRelocation {
            offset: 2,
            target: LinkRelocationTarget::GotPcRelativeSymbol("helper"),
            addend: -4,
        };
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xff, 0x25, 0, 0, 0, 0],
            readonly_data: &[],
            relocations: &[relocation],
        };
        let helper = LinkInput {
            symbol: "helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xb8, 42, 0, 0, 0, 0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let linked = link_x86_64_static::<64>(&[entry, helper], "entry").unwrap();
        assert_eq!(&linked.bytes()[..6], &[0x90, 0xe9, 10, 0, 0, 0]);

        let invalid = LinkInput {
            text: &[0x48, 0x8b, 0, 0, 0, 0],
            ..entry
        };
        assert_eq!(
            link_x86_64_static::<64>(&[invalid, helper], "entry"),
            Err(LinkerError::UnsupportedElf)
        );
    }

    #[test]
    fn relaxes_only_validated_static_gotpcrel_readonly_loads() {
        let relocation = LinkRelocation {
            offset: 3,
            target: LinkRelocationTarget::GotPcRelativeReadonlyData(0),
            addend: -4,
        };
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0x48, 0x8b, 0x0d, 0, 0, 0, 0, 0xc3],
            readonly_data: &42u64.to_le_bytes(),
            relocations: &[relocation],
        };
        let linked = link_x86_64_static::<64>(&[input], "entry").unwrap();
        assert_eq!(&linked.bytes()[..7], &[0x48, 0x8d, 0x0d, 9, 0, 0, 0]);
        assert_eq!(&linked.bytes()[16..24], &42u64.to_le_bytes());

        let invalid = LinkInput {
            text: &[0x48, 0x03, 0x05, 0, 0, 0, 0, 0xc3],
            ..input
        };
        assert_eq!(
            link_x86_64_static::<64>(&[invalid], "entry"),
            Err(LinkerError::UnsupportedElf)
        );
    }

    #[test]
    fn archive_selection_matches_additional_definitions() {
        let definitions = [LinkDefinition {
            symbol: "entry",
            target: LinkDefinitionTarget::Text(1),
        }];
        let input = LinkInput {
            symbol: "other",
            symbol_target: LinkDefinitionTarget::Text(0),
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
            symbol_target: LinkDefinitionTarget::Text(0),
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
        let caller_inventory = inventory_x86_64_coff_symbols(caller.bytes()).unwrap();
        assert_eq!(
            caller_inventory
                .symbols()
                .collect::<Result<std::vec::Vec<_>, _>>()
                .unwrap(),
            &[
                CoffObjectSymbol {
                    name: "entry",
                    kind: CoffObjectSymbolKind::Definition,
                },
                CoffObjectSymbol {
                    name: "answer_helper",
                    kind: CoffObjectSymbolKind::Reference,
                },
            ]
        );
        let callee_inventory = inventory_x86_64_coff_symbols(callee.bytes()).unwrap();
        assert_eq!(
            callee_inventory.symbols().next(),
            Some(Ok(CoffObjectSymbol {
                name: "answer_helper",
                kind: CoffObjectSymbolKind::Definition,
            }))
        );
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
    fn inventories_bounded_amd64_short_import_code_objects() {
        let mut object = std::vec![0u8; 20];
        object[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        object[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
        object[18..20].copy_from_slice(&4u16.to_le_bytes());
        object.extend_from_slice(b"WaitOnAddress\0api-ms-win-core-synch-l1-2-0.dll\0");
        let payload_size = u32::try_from(object.len() - 20).unwrap();
        object[12..16].copy_from_slice(&payload_size.to_le_bytes());

        let inventory = inventory_x86_64_coff_symbols(&object).unwrap();
        assert_eq!(
            inventory.symbols().collect::<Result<std::vec::Vec<_>, _>>(),
            Ok(std::vec![CoffObjectSymbol {
                name: "WaitOnAddress",
                kind: CoffObjectSymbolKind::Definition,
            }])
        );
        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let input = decode_x86_64_coff_short_import(&object, &mut relocations)
            .unwrap()
            .unwrap();
        assert_eq!(input.symbol, "WaitOnAddress");
        assert_eq!(input.text, &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(
            input.relocations,
            &[LinkRelocation {
                offset: 2,
                target: LinkRelocationTarget::PeImportAddress {
                    library: "api-ms-win-core-synch-l1-2-0.dll",
                    symbol: "WaitOnAddress",
                },
                addend: -4,
            }]
        );

        let mut data_import = object.clone();
        data_import[18..20].copy_from_slice(&5u16.to_le_bytes());
        assert!(matches!(
            inventory_x86_64_coff_symbols(&data_import),
            Err(LinkerError::UnsupportedCoff)
        ));
        let mut trailing = object.clone();
        trailing.push(0);
        assert!(matches!(
            inventory_x86_64_coff_symbols(&trailing),
            Err(LinkerError::InvalidCoff)
        ));
    }

    #[test]
    fn decodes_text_comdat_selection_and_rejects_unsupported_modes() {
        let mut object = std::vec![0u8; 119];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&1u16.to_le_bytes());
        object[8..12].copy_from_slice(&61u32.to_le_bytes());
        object[12..16].copy_from_slice(&3u32.to_le_bytes());
        object[20..27].copy_from_slice(b".text$x");
        object[36..40].copy_from_slice(&1u32.to_le_bytes());
        object[40..44].copy_from_slice(&60u32.to_le_bytes());
        object[56..60].copy_from_slice(&0x6050_1020u32.to_le_bytes());
        object[60] = 0xc3;
        object[61..68].copy_from_slice(b".text$x");
        object[73..75].copy_from_slice(&1i16.to_le_bytes());
        object[77] = 3;
        object[78] = 1;
        object[93] = 2;
        object[97..102].copy_from_slice(b"entry");
        object[109..111].copy_from_slice(&1i16.to_le_bytes());
        object[113] = 2;
        object[115..119].copy_from_slice(&4u32.to_le_bytes());

        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Ok(CoffTextComdatSelection::Any)
        );
        object[93] = 3;
        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Ok(CoffTextComdatSelection::SameSize)
        );
        object[93] = 4;
        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Ok(CoffTextComdatSelection::ExactMatch)
        );
        object[93] = 6;
        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Ok(CoffTextComdatSelection::Largest)
        );
        object[93] = 5;
        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Err(LinkerError::InvalidCoffAssociation)
        );
        object[93] = 2;
        object[56..60].copy_from_slice(&0x6050_0020u32.to_le_bytes());
        assert_eq!(
            x86_64_coff_text_fragment_comdat_selection(&object, 0),
            Err(LinkerError::InvalidCoffAssociation)
        );
    }

    #[test]
    fn inventories_associative_coff_sections_and_rejects_cycles() {
        let mut object = std::vec![0u8; 199];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&2u16.to_le_bytes());
        object[8..12].copy_from_slice(&105u32.to_le_bytes());
        object[12..16].copy_from_slice(&5u32.to_le_bytes());

        object[20..27].copy_from_slice(b".text$x");
        object[36..40].copy_from_slice(&1u32.to_le_bytes());
        object[40..44].copy_from_slice(&100u32.to_le_bytes());
        object[56..60].copy_from_slice(&0x6050_1020u32.to_le_bytes());
        object[60..68].copy_from_slice(b".xdata$x");
        object[76..80].copy_from_slice(&4u32.to_le_bytes());
        object[80..84].copy_from_slice(&101u32.to_le_bytes());
        object[96..100].copy_from_slice(&0x4030_1040u32.to_le_bytes());
        object[100] = 0xc3;
        object[101..105].copy_from_slice(&[1, 2, 3, 4]);

        object[105..112].copy_from_slice(b".text$x");
        object[117..119].copy_from_slice(&1i16.to_le_bytes());
        object[121] = 3;
        object[122] = 1;
        object[137] = 2;
        object[141..146].copy_from_slice(b"entry");
        object[153..155].copy_from_slice(&1i16.to_le_bytes());
        object[157] = 2;
        object[159..167].copy_from_slice(b".xdata$x");
        object[171..173].copy_from_slice(&2i16.to_le_bytes());
        object[175] = 3;
        object[176] = 1;
        object[189..191].copy_from_slice(&1u16.to_le_bytes());
        object[191] = 5;
        object[195..199].copy_from_slice(&4u32.to_le_bytes());

        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        assert_eq!(inventory.sections().len(), 2);
        assert_eq!(
            inventory.section(2),
            Some(CoffComdatSection {
                section_number: 2,
                selection: CoffTextComdatSelection::Associative,
                associated_section: Some(1),
            })
        );

        object[135..137].copy_from_slice(&2u16.to_le_bytes());
        object[137] = 5;
        assert_eq!(
            inventory_x86_64_coff_comdat_sections(&object),
            Err(LinkerError::InvalidCoffAssociation)
        );
        object[135..137].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            inventory_x86_64_coff_comdat_sections(&object),
            Err(LinkerError::InvalidCoffAssociation)
        );
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

        let mut excessive_sections = [0u8; 256];
        excessive_sections[..object.len()].copy_from_slice(object.bytes());
        excessive_sections[2..4].copy_from_slice(&257u16.to_le_bytes());
        let mut excessive_storage = empty_storage;
        assert_eq!(
            decode_x86_64_coff(&excessive_sections[..object.len()], &mut excessive_storage),
            Err(LinkerError::InvalidCoff)
        );

        let mut wrong_relocation = wrong_machine;
        wrong_relocation[..object.len()].copy_from_slice(object.bytes());
        let relocation_offset = usize::try_from(read_u32(object.bytes(), 44).unwrap()).unwrap();
        wrong_relocation[relocation_offset + 8..relocation_offset + 10]
            .copy_from_slice(&3u16.to_le_bytes());
        let mut relocation_storage = empty_storage;
        assert_eq!(
            decode_x86_64_coff(&wrong_relocation[..object.len()], &mut relocation_storage),
            Err(LinkerError::UnsupportedCoffRelocation)
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
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let decoded =
            decode_x86_64_coff_with_definitions(&bytes, &mut relocations, &mut definitions)
                .unwrap();
        assert_eq!(
            decoded.additional_definitions,
            &[LinkDefinition {
                symbol: "second",
                target: LinkDefinitionTarget::Text(6),
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
            target: LinkDefinitionTarget::Text(0),
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
    fn retains_typed_pe_tls_secrel_targets() {
        let object = coff_with_tls_secrel_relocation();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let decoded = decode_x86_64_coff_text_fragment_with_section_identities_from_inventory(
            &object,
            0,
            &inventory,
            9,
            &mut relocations,
            &mut definitions,
        )
        .unwrap();
        assert_eq!(
            decoded.relocations,
            &[LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::PeTlsSection {
                    identity: CoffSectionIdentity::new(9, 2).unwrap(),
                    offset: 0,
                },
                addend: 0,
            }]
        );

        let mut unsupported = object.clone();
        unsupported[116..118].copy_from_slice(&10u16.to_le_bytes());
        let unsupported_inventory = inventory_x86_64_coff_comdat_sections(&unsupported).unwrap();
        assert_eq!(
            decode_x86_64_coff_text_fragment_with_section_identities_from_inventory(
                &unsupported,
                0,
                &unsupported_inventory,
                9,
                &mut relocations,
                &mut definitions,
            ),
            Err(LinkerError::UnsupportedCoffRelocation)
        );
    }

    #[test]
    fn admits_pinned_sysroot_scale_and_rejects_the_next_coff_section() {
        let mut object = two_fragment_coff();
        object[2..4].copy_from_slice(&(MAX_COFF_SECTIONS as u16).to_le_bytes());
        assert_eq!(
            x86_64_coff_text_fragment_count(&object),
            Err(LinkerError::InvalidCoff)
        );
        object[2..4].copy_from_slice(&((MAX_COFF_SECTIONS + 1) as u16).to_le_bytes());
        assert_eq!(
            x86_64_coff_text_fragment_count(&object),
            Err(LinkerError::TooManyCoffSections)
        );
    }

    #[test]
    fn validates_and_discards_bounded_coff_debug_sections() {
        fn decode(object: &[u8]) -> Result<(), LinkerError> {
            let mut relocations = [LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::Symbol("unused"),
                addend: 0,
            }; MAX_LINK_RELOCATIONS];
            let mut definitions = [LinkDefinition {
                symbol: "unused",
                target: LinkDefinitionTarget::Text(0),
            }; MAX_LINK_DEFINITIONS];
            decode_x86_64_coff_text_fragment(object, 0, &mut relocations, &mut definitions)
                .map(|_| ())
        }

        let object = two_fragment_coff_with_discardable_debug();
        assert_eq!(decode(&object), Ok(()));

        let mut retained = object.clone();
        retained[136..140].copy_from_slice(&0x4030_0040u32.to_le_bytes());
        assert_eq!(decode(&retained), Err(LinkerError::UnsupportedCoff));
        let mut bad_target = object.clone();
        bad_target[165..169].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(decode(&bad_target), Err(LinkerError::InvalidCoff));
        let mut bad_kind = object.clone();
        bad_kind[169..171].copy_from_slice(&17u16.to_le_bytes());
        assert_eq!(decode(&bad_kind), Err(LinkerError::UnsupportedCoff));
        let mut bad_field = object;
        bad_field[161..165].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            decode(&bad_field),
            Err(LinkerError::InvalidRelocationOffset)
        );
        let mut truncated_field = two_fragment_coff_with_discardable_debug();
        truncated_field[161..165].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            decode(&truncated_field),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn retains_only_readonly_comdats_associated_with_each_text_fragment() {
        let object = two_fragment_coff_with_associative_readonly();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        let mut first_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut second_relocations = first_relocations;
        let mut first_definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let mut second_definitions = first_definitions;
        let first = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            0,
            &inventory,
            &mut first_relocations,
            &mut first_definitions,
        )
        .unwrap();
        let second = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            1,
            &inventory,
            &mut second_relocations,
            &mut second_definitions,
        )
        .unwrap();
        assert_eq!(first.readonly_data, b"A");
        assert_eq!(second.readonly_data, b"B");

        let mut detached = object.clone();
        detached[184 + 9 * 18 + 12..184 + 9 * 18 + 14].copy_from_slice(&1u16.to_le_bytes());
        let detached_inventory = inventory_x86_64_coff_comdat_sections(&detached).unwrap();
        assert_eq!(
            decode_x86_64_coff_text_fragment_from_inventory(
                &detached,
                1,
                &detached_inventory,
                &mut second_relocations,
                &mut second_definitions,
            )
            .unwrap()
            .readonly_data,
            b""
        );
    }

    #[test]
    fn projects_associative_readonly_comdats_as_typed_section_identities() {
        let object = two_fragment_coff_with_associative_readonly();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        assert_eq!(
            x86_64_coff_section_identity_readonly_fragment_count(&object, &inventory),
            Ok(2)
        );

        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let text = decode_x86_64_coff_text_fragment_with_section_identities_from_inventory(
            &object,
            0,
            &inventory,
            7,
            &mut relocations,
            &mut definitions,
        )
        .unwrap();
        assert!(text.readonly_data.is_empty());
        assert!(text.additional_definitions.iter().any(|definition| {
            matches!(
                definition.target,
                LinkDefinitionTarget::CoffTextSection { identity, offset: 0 }
                    if identity.object() == 7 && identity.section() == 1
            )
        }));

        let mut second_definitions = definitions;
        let first = decode_x86_64_coff_section_identity_readonly_fragment(
            &object,
            0,
            &inventory,
            7,
            &mut second_definitions,
        )
        .unwrap();
        let second = decode_x86_64_coff_section_identity_readonly_fragment(
            &object,
            1,
            &inventory,
            7,
            &mut definitions,
        )
        .unwrap();
        assert_eq!(first.input.readonly_data, b"A");
        assert_eq!(first.associated_section, Some(1));
        assert_eq!(
            first.input.symbol_target,
            LinkDefinitionTarget::CoffSection {
                identity: CoffSectionIdentity::new(7, first.section_number).unwrap(),
                offset: 0,
            }
        );
        assert_eq!(second.input.readonly_data, b"B");
        assert_eq!(second.associated_section, Some(3));
        assert_ne!(first.input.symbol_target, second.input.symbol_target);
    }

    #[test]
    fn assigns_associative_readonly_relocations_to_exact_text_roots() {
        let object = two_fragment_coff_with_associative_readonly_relocations();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        let decoded =
            decode_x86_64_coff_readonly_absolute_relocations_from_inventory(&object, &inventory)
                .unwrap();
        assert_eq!(
            decoded.relocations(),
            &[
                PeReadonlyAbsoluteRelocation {
                    readonly_owner: "entry",
                    readonly_identity: None,
                    readonly_offset: 0,
                    target_symbol: "helper",
                    target_identity: None,
                    target_offset: 0,
                    addend: 3,
                    kind: PeReadonlyRelocationKind::Address64,
                },
                PeReadonlyAbsoluteRelocation {
                    readonly_owner: "helper",
                    readonly_identity: None,
                    readonly_offset: 0,
                    target_symbol: "entry",
                    target_identity: None,
                    target_offset: 0,
                    addend: -2,
                    kind: PeReadonlyRelocationKind::Address64,
                },
            ]
        );

        let mut first_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut second_relocations = first_relocations;
        let mut first_definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let mut second_definitions = first_definitions;
        let first = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            0,
            &inventory,
            &mut first_relocations,
            &mut first_definitions,
        )
        .unwrap();
        let second = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            1,
            &inventory,
            &mut second_relocations,
            &mut second_definitions,
        )
        .unwrap();
        let image = link_x86_64_pe_with_data_unwind_and_readonly_relocations::<2048, 8192>(
            &[first, second],
            "entry",
            &[],
            &[],
            decoded.relocations(),
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(image.bytes()[0x400..0x408].try_into().unwrap()),
            0x0000_0001_4000_1013
        );
        assert_eq!(
            u64::from_le_bytes(image.bytes()[0x410..0x418].try_into().unwrap()),
            0x0000_0001_4000_0ffe
        );
    }

    #[test]
    fn decodes_nonassociative_readonly_comdats_as_named_link_inputs() {
        let object = coff_with_standalone_readonly_comdat();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        assert_eq!(
            x86_64_coff_standalone_readonly_fragment_count(&object, &inventory),
            Ok(1)
        );
        let substituted = object.clone();
        assert_eq!(
            x86_64_coff_standalone_readonly_fragment_count(&substituted, &inventory),
            Err(LinkerError::InvalidCoffAssociation)
        );
        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut text_definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let mut readonly_definitions = text_definitions;
        let text = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            0,
            &inventory,
            &mut relocations,
            &mut text_definitions,
        )
        .unwrap();
        assert!(text.readonly_data.is_empty());
        assert_eq!(
            text.relocations,
            &[LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::Symbol("literal"),
                addend: -4,
            }]
        );
        let readonly = decode_x86_64_coff_standalone_readonly_fragment(
            &object,
            0,
            &inventory,
            &mut readonly_definitions,
        )
        .unwrap();
        assert_eq!(readonly.selection, CoffTextComdatSelection::Any);
        assert_eq!(readonly.input.symbol, "literal");
        assert_eq!(
            readonly.input.symbol_target,
            LinkDefinitionTarget::ReadonlyData(0)
        );
        assert_eq!(readonly.input.readonly_data, b"R");
        let linked = link_x86_64_static::<64>(&[text, readonly.input], "entry").unwrap();
        assert_eq!(linked.readonly_offset(), 16);
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            12
        );
        assert_eq!(linked.bytes()[16], b'R');
    }

    #[test]
    fn resolves_object_local_standalone_readonly_comdats() {
        let mut object = coff_with_standalone_readonly_comdat();
        object[115 + 5 * 18 + 16] = 3;
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        let mut relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("unused"),
            addend: 0,
        }; MAX_LINK_RELOCATIONS];
        let mut text_definitions = [LinkDefinition {
            symbol: "unused",
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let mut readonly_definitions = text_definitions;
        let text = decode_x86_64_coff_text_fragment_from_inventory(
            &object,
            0,
            &inventory,
            &mut relocations,
            &mut text_definitions,
        )
        .unwrap();
        assert_eq!(
            text.relocations,
            &[LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::LocalSymbol("literal"),
                addend: -4,
            }]
        );
        let readonly = decode_x86_64_coff_standalone_readonly_fragment(
            &object,
            0,
            &inventory,
            &mut readonly_definitions,
        )
        .unwrap();
        assert_eq!(readonly.input.symbol, "literal");
        let linked = link_x86_64_static::<64>(&[text, readonly.input], "entry").unwrap();
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            12
        );
    }

    #[test]
    fn accepts_only_non_loadable_remove_directives_with_bounded_exclusions() {
        let mut object = [0u8; 64];
        let header = 20;
        object[header + 36..header + 40].copy_from_slice(&0x0010_0a00u32.to_le_bytes());
        assert_eq!(
            validate_discardable_coff_exclude_directives(
                &object,
                header,
                b"-exclude-symbols:__divmoddi4 ",
                0,
            ),
            Ok(())
        );
        assert_eq!(
            validate_discardable_coff_exclude_directives(
                &object,
                header,
                b"-defaultlib:legacy.lib",
                0,
            ),
            Err(LinkerError::UnsupportedCoffSection)
        );
        object[header + 36..header + 40].copy_from_slice(&0x2010_0a00u32.to_le_bytes());
        assert_eq!(
            validate_discardable_coff_exclude_directives(
                &object,
                header,
                b"-exclude-symbols:__divmoddi4",
                0,
            ),
            Err(LinkerError::UnsupportedCoffSection)
        );
    }

    #[test]
    fn decodes_multiple_readonly_relocation_kinds_from_named_comdats() {
        let object = coff_with_multiple_standalone_readonly_relocations();
        let inventory = inventory_x86_64_coff_comdat_sections(&object).unwrap();
        let decoded =
            decode_x86_64_coff_readonly_absolute_relocations_from_inventory(&object, &inventory)
                .unwrap();
        assert_eq!(
            decoded.relocations(),
            &[
                PeReadonlyAbsoluteRelocation {
                    readonly_owner: "literal",
                    readonly_identity: None,
                    readonly_offset: 0,
                    target_symbol: "entry",
                    target_identity: None,
                    target_offset: 0,
                    addend: 5,
                    kind: PeReadonlyRelocationKind::Address32NoBase,
                },
                PeReadonlyAbsoluteRelocation {
                    readonly_owner: "literal",
                    readonly_identity: None,
                    readonly_offset: 8,
                    target_symbol: "literal",
                    target_identity: None,
                    target_offset: 0,
                    addend: -4,
                    kind: PeReadonlyRelocationKind::Address64,
                },
            ]
        );
        let identified =
            decode_x86_64_coff_readonly_absolute_relocations_with_section_identities_from_inventory(
                &object,
                &inventory,
                9,
            )
            .unwrap();
        assert_eq!(identified.relocations().len(), 2);
        assert!(identified.relocations().iter().all(|relocation| {
            relocation.readonly_identity
                == Some(CoffSectionIdentity::new(9, 2).unwrap())
        }));
        assert_eq!(identified.relocations()[0].readonly_offset, 0);
        assert_eq!(identified.relocations()[1].readonly_offset, 8);

        for (coff_kind, trailing_bytes) in (4u16..=9).zip(0u8..=5) {
            let mut relative = object.clone();
            relative[138..140].copy_from_slice(&coff_kind.to_le_bytes());
            let relative_inventory = inventory_x86_64_coff_comdat_sections(&relative).unwrap();
            let relative_decoded = decode_x86_64_coff_readonly_absolute_relocations_from_inventory(
                &relative,
                &relative_inventory,
            )
            .unwrap();
            assert_eq!(
                relative_decoded.relocations()[1],
                PeReadonlyAbsoluteRelocation {
                    readonly_owner: "literal",
                    readonly_identity: None,
                    readonly_offset: 8,
                    target_symbol: "literal",
                    target_identity: None,
                    target_offset: 0,
                    addend: -4,
                    kind: PeReadonlyRelocationKind::Relative32 { trailing_bytes },
                }
            );
        }

        let substituted = object.clone();
        assert_eq!(
            decode_x86_64_coff_readonly_absolute_relocations_from_inventory(
                &substituted,
                &inventory,
            ),
            Err(LinkerError::InvalidCoffAssociation)
        );
        let mut unsupported = object.clone();
        unsupported[128..130].copy_from_slice(&10u16.to_le_bytes());
        let unsupported_inventory = inventory_x86_64_coff_comdat_sections(&unsupported).unwrap();
        assert_eq!(
            decode_x86_64_coff_readonly_absolute_relocations_from_inventory(
                &unsupported,
                &unsupported_inventory,
            ),
            Err(LinkerError::UnsupportedCoffRelocation)
        );
        let mut out_of_bounds = object;
        out_of_bounds[120..124].copy_from_slice(&13u32.to_le_bytes());
        let out_of_bounds_inventory =
            inventory_x86_64_coff_comdat_sections(&out_of_bounds).unwrap();
        assert_eq!(
            decode_x86_64_coff_readonly_absolute_relocations_from_inventory(
                &out_of_bounds,
                &out_of_bounds_inventory,
            ),
            Err(LinkerError::InvalidRelocationOffset)
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
            target: LinkDefinitionTarget::Text(0),
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
            target: LinkDefinitionTarget::Text(0),
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
            Err(LinkerError::UnsupportedCoffSection)
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
            Err(LinkerError::UnsupportedCoffSection)
        );
    }

    #[test]
    fn decodes_typed_addr32nb_runtime_function_records() {
        let object = coff_with_one_runtime_function();
        assert_eq!(x86_64_coff_text_fragment_count(&object), Ok(1));
        assert_eq!(x86_64_coff_unwind_section_count(&object), Ok(2));
        let mut storage = [PeRuntimeFunction {
            begin_symbol: "unused",
            begin_identity: None,
            begin_offset: 0,
            end_symbol: "unused",
            end_identity: None,
            end_offset: 0,
            unwind_info: &[],
        }; MAX_PE_RUNTIME_FUNCTIONS];
        let records = decode_x86_64_coff_runtime_functions(&object, &mut storage).unwrap();
        assert_eq!(
            records,
            &[PeRuntimeFunction {
                begin_symbol: "entry",
                begin_identity: None,
                begin_offset: 0,
                end_symbol: "entry",
                end_identity: None,
                end_offset: 1,
                unwind_info: &[1, 2, 3, 4],
            }]
        );
        let mut identity_storage = storage;
        let identified = decode_x86_64_coff_runtime_functions_with_section_identities(
            &object,
            9,
            &mut identity_storage,
        )
        .unwrap();
        assert_eq!(
            identified[0].begin_identity,
            Some(CoffSectionIdentity::new(9, 1).unwrap())
        );
        assert_eq!(identified[0].end_identity, identified[0].begin_identity);

        let mut invalid = object.clone();
        invalid[157 + 8..157 + 10].copy_from_slice(&4u16.to_le_bytes());
        let mut invalid_storage = [PeRuntimeFunction {
            begin_symbol: "unused",
            begin_identity: None,
            begin_offset: 0,
            end_symbol: "unused",
            end_identity: None,
            end_offset: 0,
            unwind_info: &[],
        }; MAX_PE_RUNTIME_FUNCTIONS];
        assert_eq!(
            decode_x86_64_coff_runtime_functions(&invalid, &mut invalid_storage),
            Err(LinkerError::UnsupportedCoffRelocation)
        );

        let mut aliased = object.clone();
        aliased.resize(335, 0);
        aliased.copy_within(313..317, 331);
        aliased[12..16].copy_from_slice(&8u32.to_le_bytes());
        aliased[313..318].copy_from_slice(b"alias");
        aliased[325..327].copy_from_slice(&1i16.to_le_bytes());
        aliased[329] = 2;
        let mut aliased_storage = storage;
        assert_eq!(
            decode_x86_64_coff_runtime_functions(&aliased, &mut aliased_storage)
                .unwrap()[0]
                .begin_symbol,
            "entry"
        );

        let mut detached = object.clone();
        detached[273] = 2;
        detached[67] = b'b';
        let mut detached_storage = [PeRuntimeFunction {
            begin_symbol: "unused",
            begin_identity: None,
            begin_offset: 0,
            end_symbol: "unused",
            end_identity: None,
            end_offset: 0,
            unwind_info: &[],
        }; MAX_PE_RUNTIME_FUNCTIONS];
        assert_eq!(
            decode_x86_64_coff_runtime_functions(&detached, &mut detached_storage),
            Err(LinkerError::InvalidCoffAssociation)
        );
    }

    #[test]
    fn decodes_typed_addr64_writable_coff_data() {
        let object = coff_with_readonly_and_writable_data();
        assert_eq!(x86_64_coff_writable_section_count(&object), Ok(1));
        let mut storage = [PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "unused",
                offset: 0,
            },
        }; MAX_LINK_RELOCATIONS];
        let writable = decode_x86_64_coff_writable_data(&object, "entry", &mut storage)
            .unwrap()
            .unwrap();
        assert_eq!(writable.initialized, &[0; 8]);
        assert_eq!(writable.zeroed_size, 0);
        assert_eq!(writable.selection, PeWritableComdatSelection::None);
        assert_eq!(
            writable.relocations,
            &[PeWritableRelocation {
                offset: 0,
                target: PeWritableRelocationTarget::Readonly {
                    owner: "entry",
                    offset: 0,
                },
            }]
        );
        let mut fragment_storage = [PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "unused",
                offset: 0,
            },
        }; MAX_LINK_RELOCATIONS];
        let fragment =
            decode_x86_64_coff_writable_data_fragment(&object, 0, "entry", &mut fragment_storage)
                .unwrap();
        assert_eq!(fragment, writable);

        let mut text_target = object.clone();
        text_target[153 + 4..153 + 8].copy_from_slice(&0u32.to_le_bytes());
        let mut text_storage = storage;
        let text_writable =
            decode_x86_64_coff_writable_data(&text_target, "entry", &mut text_storage)
                .unwrap()
                .unwrap();
        assert_eq!(
            text_writable.relocations,
            &[PeWritableRelocation {
                offset: 0,
                target: PeWritableRelocationTarget::TextSymbol("entry"),
            }]
        );

        let mut tls_target = object.clone();
        tls_target[56..60].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        tls_target[60..68].fill(0);
        tls_target[60..66].copy_from_slice(b".tls$a");
        tls_target[96..100].copy_from_slice(&0xc000_0040u32.to_le_bytes());
        tls_target[136..140].copy_from_slice(&0xc040_0040u32.to_le_bytes());
        let mut tls_storage = storage;
        let tls_writable = decode_x86_64_coff_writable_data_fragment_with_section_identities(
            &tls_target,
            0,
            "entry",
            9,
            &mut tls_storage,
        )
        .unwrap();
        assert_eq!(
            tls_writable.relocations,
            &[PeWritableRelocation {
                offset: 0,
                target: PeWritableRelocationTarget::TlsSection {
                    identity: CoffSectionIdentity::new(9, 2).unwrap(),
                    offset: 0,
                },
            }]
        );
        let mut missing_storage = [PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "unused",
                offset: 0,
            },
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
    fn decodes_any_writable_comdat_and_rejects_unsupported_selection() {
        let object = coff_with_any_writable_comdat();
        let mut unsupported = object.clone();
        unsupported[231] = 5;
        let mut storage = [PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "unused",
                offset: 0,
            },
        }; MAX_LINK_RELOCATIONS];
        let writable = decode_x86_64_coff_writable_data(&object, "entry", &mut storage)
            .unwrap()
            .unwrap();
        assert_eq!(writable.selection, PeWritableComdatSelection::Any);

        let mut unsupported_storage = [PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "unused",
                offset: 0,
            },
        }; MAX_LINK_RELOCATIONS];
        assert_eq!(
            decode_x86_64_coff_writable_data(&unsupported, "entry", &mut unsupported_storage,),
            Err(LinkerError::UnsupportedCoff)
        );
    }

    #[test]
    fn selects_leftmost_any_writable_comdat_and_rejects_other_duplicates() {
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let first = PeWritableData {
            symbol: "shared",
            selection: PeWritableComdatSelection::Any,
            initialized: &[1; 8],
            zeroed_size: 0,
            relocations: &[],
        };
        let second = PeWritableData {
            initialized: &[2; 8],
            ..first
        };
        let pe = link_x86_64_pe_with_data_and_unwind::<2048, 8192>(
            &[input],
            "entry",
            &[],
            &[first, second],
        )
        .unwrap();
        assert_eq!(&pe.bytes()[0x400..0x408], &[1; 8]);

        let duplicate = PeWritableData {
            selection: PeWritableComdatSelection::NoDuplicates,
            ..second
        };
        assert_eq!(
            link_x86_64_pe_with_data_and_unwind::<2048, 8192>(
                &[input],
                "entry",
                &[],
                &[first, duplicate],
            ),
            Err(LinkerError::DuplicateSymbol)
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
            target: LinkDefinitionTarget::Text(0),
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
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3],
            readonly_data: b"hello",
            relocations: &[relocation],
        };
        let pe = link_x86_64_pe::<2048, 8192>(&[input], "entry").unwrap();
        assert_eq!(&pe.bytes()[..2], b"MZ");
        assert_eq!(&pe.bytes()[0x80..0x84], b"PE\0\0");
        assert_eq!(read_u16(pe.bytes(), 0x84).unwrap(), 0x8664);
        assert_eq!(read_u16(pe.bytes(), 0x96).unwrap(), 0x022f);
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

        let mut caller_owned = [0xa5; 2048];
        let caller_length =
            link_x86_64_pe_with_data_unwind_and_readonly_relocations_into::<8192>(
                &[input],
                "entry",
                &[],
                &[],
                &[],
                &mut caller_owned,
            )
            .unwrap();
        assert_eq!(&caller_owned[..caller_length], pe.bytes());
        assert!(caller_owned[caller_length..].iter().all(|byte| *byte == 0));

        let mut too_small = [0u8; 512];
        assert_eq!(
            link_x86_64_pe_with_data_unwind_and_readonly_relocations_into::<8192>(
                &[input],
                "entry",
                &[],
                &[],
                &[],
                &mut too_small,
            ),
            Err(LinkerError::OutputTooSmall)
        );
    }

    #[test]
    fn emits_sorted_pe_runtime_functions_and_readonly_unwind_bytes() {
        let inputs = [
            LinkInput {
                symbol: "entry",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
            LinkInput {
                symbol: "helper",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0xc3],
                readonly_data: &[],
                relocations: &[],
            },
        ];
        let runtime_functions = [
            PeRuntimeFunction {
                begin_symbol: "helper",
                begin_identity: None,
                begin_offset: 0,
                end_symbol: "helper",
                end_identity: None,
                end_offset: 1,
                unwind_info: &[1, 2, 3, 4],
            },
            PeRuntimeFunction {
                begin_symbol: "entry",
                begin_identity: None,
                begin_offset: 0,
                end_symbol: "entry",
                end_identity: None,
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
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &42u64.to_le_bytes(),
            relocations: &[],
        };
        let relocation = PeWritableRelocation {
            offset: 0,
            target: PeWritableRelocationTarget::Readonly {
                owner: "entry",
                offset: 0,
            },
        };
        let writable = PeWritableData {
            symbol: "writable",
            selection: PeWritableComdatSelection::None,
            initialized: &[0; 8],
            zeroed_size: 0,
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

    #[test]
    fn resolves_readonly_absolute_targets_and_checked_addends_after_layout() {
        let definitions = [LinkDefinition {
            symbol: "readonly_target",
            target: LinkDefinitionTarget::ReadonlyData(16),
        }];
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &definitions,
            text: &[0xc3],
            readonly_data: &[0; 32],
            relocations: &[],
        };
        let writable = PeWritableData {
            symbol: "writable",
            selection: PeWritableComdatSelection::None,
            initialized: &[0; 8],
            zeroed_size: 0,
            relocations: &[],
        };
        let relocations = [
            PeReadonlyAbsoluteRelocation {
                readonly_owner: "entry",
                readonly_identity: None,
                readonly_offset: 0,
                target_symbol: "entry",
                target_identity: None,
                target_offset: 0,
                addend: 3,
                kind: PeReadonlyRelocationKind::Address64,
            },
            PeReadonlyAbsoluteRelocation {
                readonly_owner: "entry",
                readonly_identity: None,
                readonly_offset: 8,
                target_symbol: "readonly_target",
                target_identity: None,
                target_offset: 0,
                addend: -4,
                kind: PeReadonlyRelocationKind::Address64,
            },
            PeReadonlyAbsoluteRelocation {
                readonly_owner: "entry",
                readonly_identity: None,
                readonly_offset: 16,
                target_symbol: "writable",
                target_identity: None,
                target_offset: 0,
                addend: 7,
                kind: PeReadonlyRelocationKind::Address64,
            },
            PeReadonlyAbsoluteRelocation {
                readonly_owner: "entry",
                readonly_identity: None,
                readonly_offset: 24,
                target_symbol: "readonly_target",
                target_identity: None,
                target_offset: 0,
                addend: -1,
                kind: PeReadonlyRelocationKind::Address32NoBase,
            },
            PeReadonlyAbsoluteRelocation {
                readonly_owner: "entry",
                readonly_identity: None,
                readonly_offset: 28,
                target_symbol: "entry",
                target_identity: None,
                target_offset: 0,
                addend: 2,
                kind: PeReadonlyRelocationKind::Relative32 { trailing_bytes: 5 },
            },
        ];
        let pe = link_x86_64_pe_with_data_unwind_and_readonly_relocations::<2048, 8192>(
            &[input],
            "entry",
            &[],
            &[writable],
            &relocations,
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(pe.bytes()[0x400..0x408].try_into().unwrap()),
            0x0000_0001_4000_1003
        );
        assert_eq!(
            u64::from_le_bytes(pe.bytes()[0x408..0x410].try_into().unwrap()),
            0x0000_0001_4000_200c
        );
        assert_eq!(
            u64::from_le_bytes(pe.bytes()[0x410..0x418].try_into().unwrap()),
            0x0000_0001_4000_3007
        );
        assert_eq!(
            u32::from_le_bytes(pe.bytes()[0x418..0x41c].try_into().unwrap()),
            0x200f
        );
        assert_eq!(
            i32::from_le_bytes(pe.bytes()[0x41c..0x420].try_into().unwrap()),
            -0x1023
        );

        let underflow = [PeReadonlyAbsoluteRelocation {
            addend: i64::MIN,
            ..relocations[0]
        }];
        assert_eq!(
            link_x86_64_pe_with_data_unwind_and_readonly_relocations::<2048, 8192>(
                &[input],
                "entry",
                &[],
                &[writable],
                &underflow,
            ),
            Err(LinkerError::OffsetOverflow)
        );
        let rva_underflow = [PeReadonlyAbsoluteRelocation {
            addend: i64::MIN,
            ..relocations[3]
        }];
        assert_eq!(
            link_x86_64_pe_with_data_unwind_and_readonly_relocations::<2048, 8192>(
                &[input],
                "entry",
                &[],
                &[writable],
                &rva_underflow,
            ),
            Err(LinkerError::RelocationOverflow)
        );
        let invalid_relative = [PeReadonlyAbsoluteRelocation {
            kind: PeReadonlyRelocationKind::Relative32 { trailing_bytes: 6 },
            ..relocations[4]
        }];
        assert_eq!(
            link_x86_64_pe_with_data_unwind_and_readonly_relocations::<2048, 8192>(
                &[input],
                "entry",
                &[],
                &[writable],
                &invalid_relative,
            ),
            Err(LinkerError::InvalidCoff)
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn generated_pe_executes_on_the_controlled_windows_host() {
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
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
            symbol_target: LinkDefinitionTarget::Text(0),
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
        let mut grouped_data = [0u8; 1024];
        grouped_data[..data.len()].copy_from_slice(data.bytes());
        let grouped_section_offset =
            to_usize_elf(read_u64_elf(&grouped_data, 40).unwrap()).unwrap();
        let grouped_section_count = usize::from(read_u16_elf(&grouped_data, 60).unwrap());
        let group_header = (1..grouped_section_count)
            .map(|index| {
                elf_section_header(grouped_section_offset, grouped_section_count, index).unwrap()
            })
            .find(|header| read_u32_elf(&grouped_data, *header + 4).unwrap() == 4)
            .unwrap();
        let text_index =
            usize::try_from(read_u32_elf(&grouped_data, group_header + 44).unwrap()).unwrap();
        let symbols_index =
            usize::try_from(read_u32_elf(&grouped_data, group_header + 40).unwrap()).unwrap();
        let readonly_index = (1..grouped_section_count)
            .find(|index| {
                let header =
                    elf_section_header(grouped_section_offset, grouped_section_count, *index)
                        .unwrap();
                read_u32_elf(&grouped_data, header + 4).unwrap() == 1
                    && read_u64_elf(&grouped_data, header + 8).unwrap() & 0x7 == 0x2
            })
            .unwrap();
        let symbols_header =
            elf_section_header(grouped_section_offset, grouped_section_count, symbols_index)
                .unwrap();
        let symbols = elf_section_contents(
            &grouped_data,
            grouped_section_offset,
            grouped_section_count,
            symbols_index,
        )
        .unwrap();
        let strings_index =
            usize::try_from(read_u32_elf(&grouped_data, symbols_header + 40).unwrap()).unwrap();
        let strings = elf_section_contents(
            &grouped_data,
            grouped_section_offset,
            grouped_section_count,
            strings_index,
        )
        .unwrap();
        let signature_index = (1..symbols.len() / 24)
            .find(|index| {
                let record = index * 24;
                let name = usize::try_from(read_u32_elf(symbols, record).unwrap()).unwrap();
                name != 0 && elf_string(strings, name).unwrap() == "literal"
            })
            .unwrap();
        grouped_data[group_header + 4..group_header + 8].copy_from_slice(&17u32.to_le_bytes());
        grouped_data[group_header + 32..group_header + 40].copy_from_slice(&12u64.to_le_bytes());
        grouped_data[group_header + 44..group_header + 48]
            .copy_from_slice(&u32::try_from(signature_index).unwrap().to_le_bytes());
        grouped_data[group_header + 56..group_header + 64].copy_from_slice(&4u64.to_le_bytes());
        for member_index in [text_index, readonly_index] {
            let member_header =
                elf_section_header(grouped_section_offset, grouped_section_count, member_index)
                    .unwrap();
            let flags = read_u64_elf(&grouped_data, member_header + 8).unwrap() | 0x200;
            grouped_data[member_header + 8..member_header + 16]
                .copy_from_slice(&flags.to_le_bytes());
        }
        let group_offset =
            to_usize_elf(read_u64_elf(&grouped_data, group_header + 24).unwrap()).unwrap();
        grouped_data[group_offset..group_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        grouped_data[group_offset + 4..group_offset + 8]
            .copy_from_slice(&u32::try_from(text_index).unwrap().to_le_bytes());
        grouped_data[group_offset + 8..group_offset + 12]
            .copy_from_slice(&u32::try_from(readonly_index).unwrap().to_le_bytes());
        let grouped_selection =
            select_x86_64_elf_sections(&grouped_data[..data.len()], &["literal"]).unwrap();
        assert_eq!(
            grouped_selection.indices(),
            &[
                u16::try_from(text_index).unwrap(),
                u16::try_from(readonly_index).unwrap(),
            ]
        );
        grouped_data[group_offset..group_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            select_x86_64_elf_sections(&grouped_data[..data.len()], &["literal"]),
            Err(LinkerError::UnsupportedElf)
        );
        grouped_data[group_offset..group_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        grouped_data[group_offset + 8..group_offset + 12]
            .copy_from_slice(&u32::try_from(grouped_section_count).unwrap().to_le_bytes());
        assert_eq!(
            select_x86_64_elf_sections(&grouped_data[..data.len()], &["literal"]),
            Err(LinkerError::InvalidElf)
        );
        grouped_data[group_offset + 8..group_offset + 12]
            .copy_from_slice(&u32::try_from(readonly_index).unwrap().to_le_bytes());
        let duplicate_group = grouped_data;
        let grouped_link_selection = select_x86_64_elf_link_sections(
            &[&grouped_data[..data.len()], &duplicate_group[..data.len()]],
            "literal",
        )
        .unwrap();
        assert_eq!(
            grouped_link_selection.selections()[0].indices(),
            &[
                u16::try_from(text_index).unwrap(),
                u16::try_from(readonly_index).unwrap(),
            ]
        );
        assert_eq!(grouped_link_selection.selections()[1].indices(), &[]);
        let caller_selection = select_x86_64_elf_sections(caller.bytes(), &["entry"]).unwrap();
        let caller_inventory = inventory_x86_64_elf_symbols(caller.bytes()).unwrap();
        assert_eq!(
            caller_inventory.definitions(),
            &[ElfObjectSymbolDefinition {
                symbol: "entry",
                binding: ElfSelectedSymbolBinding::Global,
            }]
        );
        assert_eq!(caller_inventory.references(), &["helper"]);
        assert_eq!(caller_selection.indices(), &[1]);
        let caller_sections =
            decode_x86_64_elf_selected_sections(caller.bytes(), &caller_selection).unwrap();
        assert_eq!(caller_sections.sections().len(), 1);
        assert_eq!(caller_sections.sections()[0].name, ".text");
        assert_eq!(caller_sections.sections()[0].kind, ElfSectionKind::Text);
        assert_eq!(caller_sections.sections()[0].bytes, caller_code.bytes());
        assert_eq!(caller_sections.sections()[0].size, caller_code.len());
        assert_eq!(
            decode_x86_64_elf_selected_definitions(caller.bytes(), &caller_selection)
                .unwrap()
                .definitions(),
            &[ElfSelectedDefinition {
                name: "entry",
                section_index: 1,
                offset: 0,
                size: caller_code.len(),
                binding: ElfSelectedSymbolBinding::Global,
                visibility: ElfSelectedSymbolVisibility::Default,
                kind: ElfSelectedSymbolKind::Function,
            }]
        );
        assert_eq!(
            decode_x86_64_elf_selected_relocations(caller.bytes(), &caller_selection)
                .unwrap()
                .relocations(),
            &[ElfSelectedRelocation {
                section_index: 1,
                offset: 1,
                kind: ElfSelectedRelocationKind::PltRelative32,
                target: ElfSelectedRelocationTarget::Symbol("helper"),
                addend: -4,
            }]
        );
        let callee_selection = select_x86_64_elf_sections(callee.bytes(), &["helper"]).unwrap();
        assert_eq!(
            decode_x86_64_elf_selected_sections(caller.bytes(), &callee_selection),
            Err(LinkerError::InvalidElf)
        );

        let data_selection = select_x86_64_elf_sections(data.bytes(), &["literal"]).unwrap();
        assert_eq!(data_selection.indices(), &[1, 3]);
        let data_sections =
            decode_x86_64_elf_selected_sections(data.bytes(), &data_selection).unwrap();
        assert_eq!(data_sections.sections().len(), 2);
        assert_eq!(data_sections.sections()[0].name, ".text");
        assert_eq!(data_sections.sections()[0].kind, ElfSectionKind::Text);
        assert_eq!(data_sections.sections()[0].bytes, data_code.bytes());
        assert_eq!(data_sections.sections()[1].name, ".rodata");
        assert_eq!(
            data_sections.sections()[1].kind,
            ElfSectionKind::ReadonlyData
        );
        assert_eq!(data_sections.sections()[1].bytes, b"hello");
        assert_eq!(
            decode_x86_64_elf_selected_definitions(data.bytes(), &data_selection)
                .unwrap()
                .definitions(),
            &[ElfSelectedDefinition {
                name: "literal",
                section_index: 1,
                offset: 0,
                size: data_code.len(),
                binding: ElfSelectedSymbolBinding::Global,
                visibility: ElfSelectedSymbolVisibility::Default,
                kind: ElfSelectedSymbolKind::Function,
            }]
        );
        assert_eq!(
            decode_x86_64_elf_selected_relocations(data.bytes(), &data_selection)
                .unwrap()
                .relocations(),
            &[ElfSelectedRelocation {
                section_index: 1,
                offset: 3,
                kind: ElfSelectedRelocationKind::PcRelative32,
                target: ElfSelectedRelocationTarget::Section {
                    index: 3,
                    offset: 0,
                },
                addend: -3,
            }]
        );
        assert_eq!(
            select_x86_64_elf_sections(data.bytes(), &["missing"]),
            Err(LinkerError::UndefinedSymbol)
        );
        let caller_definitions =
            decode_x86_64_elf_selected_definitions(caller.bytes(), &caller_selection).unwrap();
        let caller_relocations =
            decode_x86_64_elf_selected_relocations(caller.bytes(), &caller_selection).unwrap();
        let callee_sections =
            decode_x86_64_elf_selected_sections(callee.bytes(), &callee_selection).unwrap();
        let callee_definitions =
            decode_x86_64_elf_selected_definitions(callee.bytes(), &callee_selection).unwrap();
        let callee_relocations =
            decode_x86_64_elf_selected_relocations(callee.bytes(), &callee_selection).unwrap();
        let data_definitions =
            decode_x86_64_elf_selected_definitions(data.bytes(), &data_selection).unwrap();
        let data_relocations =
            decode_x86_64_elf_selected_relocations(data.bytes(), &data_selection).unwrap();
        let link_selection = select_x86_64_elf_link_sections(
            &[caller.bytes(), callee.bytes(), data.bytes()],
            "entry",
        )
        .unwrap();
        assert_eq!(
            select_x86_64_elf_link_sections_detailed(&[caller.bytes()], "entry"),
            Err(ElfLinkSelectionError {
                kind: LinkerError::UndefinedSymbol,
                symbol: Some("helper"),
            })
        );
        assert_eq!(link_selection.selections()[0].indices(), &[1]);
        assert_eq!(link_selection.selections()[1].indices(), &[1]);
        assert_eq!(link_selection.selections()[2].indices(), &[]);
        let mut invalid_unused = [0u8; 1024];
        invalid_unused[..data.len()].copy_from_slice(data.bytes());
        invalid_unused[8] = 1;
        assert_eq!(
            select_x86_64_elf_link_sections(
                &[
                    caller.bytes(),
                    callee.bytes(),
                    &invalid_unused[..data.len()],
                ],
                "entry",
            ),
            Err(LinkerError::UnsupportedElf)
        );
        let selected_objects = [
            ElfSelectedObject {
                sections: &caller_sections,
                definitions: &caller_definitions,
                relocations: &caller_relocations,
            },
            ElfSelectedObject {
                sections: &callee_sections,
                definitions: &callee_definitions,
                relocations: &callee_relocations,
            },
            ElfSelectedObject {
                sections: &data_sections,
                definitions: &data_definitions,
                relocations: &data_relocations,
            },
        ];
        let selected_layout = layout_x86_64_elf_selected_sections(&selected_objects).unwrap();
        assert_eq!(
            selected_layout.sections(),
            &[
                ElfSelectedSectionLayout {
                    input_index: 0,
                    section_index: 1,
                    offset: 0,
                },
                ElfSelectedSectionLayout {
                    input_index: 1,
                    section_index: 1,
                    offset: 16,
                },
                ElfSelectedSectionLayout {
                    input_index: 2,
                    section_index: 1,
                    offset: 32,
                },
                ElfSelectedSectionLayout {
                    input_index: 2,
                    section_index: 3,
                    offset: 4096,
                },
            ]
        );
        assert_eq!(selected_layout.text_length, 40);
        assert_eq!(selected_layout.readonly_offset, 4096);
        assert_eq!(selected_layout.readonly_length, 5);
        assert_eq!(selected_layout.writable_offset, 4101);
        assert_eq!(selected_layout.file_length, 4101);
        assert_eq!(selected_layout.memory_length, 4101);
        let selected_linked =
            link_x86_64_elf_selected_sections::<8192>(&selected_objects, "entry", 0x401000)
                .unwrap();
        assert_eq!(selected_linked.entry_offset, 0);
        assert_eq!(selected_linked.length, 4101);
        assert_eq!(selected_linked.memory_length, 4101);
        assert_eq!(
            i32::from_le_bytes(selected_linked.bytes()[1..5].try_into().unwrap()),
            11
        );
        assert_eq!(
            i32::from_le_bytes(selected_linked.bytes()[35..39].try_into().unwrap()),
            4058
        );
        assert_eq!(&selected_linked.bytes()[4096..4101], b"hello");
        let selected_elf =
            link_x86_64_elf_selected_executable::<16384, 8192>(&selected_objects, "entry").unwrap();
        assert_eq!(&selected_elf.bytes()[..4], b"\x7fELF");
        assert_eq!(read_u64_elf(selected_elf.bytes(), 24).unwrap(), 0x401000);
        assert_eq!(read_u16_elf(selected_elf.bytes(), 56).unwrap(), 3);
        assert_eq!(&selected_elf.bytes()[8192..8197], b"hello");
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
    fn selected_elf_decodes_and_applies_unsigned_absolute_32_relocations() {
        let caller_code = MachineCode::<8>::from_bytes_for_test(&[0, 0, 0, 0, 0xc3]);
        let caller = emit_elf64_x86_64_with_relocation::<1024, 8>(
            "entry",
            &caller_code,
            X86_64PcRelativeRelocation {
                offset: 1,
                symbol: "helper",
                kind: X86_64PcRelativeRelocationKind::Branch,
            },
        )
        .unwrap();
        let callee_code = MachineCode::<8>::from_bytes_for_test(&[0xc3]);
        let callee = emit_elf64_x86_64::<512, 8>("helper", &callee_code).unwrap();
        let mut caller_bytes = [0u8; 1024];
        caller_bytes[..caller.len()].copy_from_slice(caller.bytes());
        let section_offset = to_usize_elf(read_u64_elf(&caller_bytes, 40).unwrap()).unwrap();
        let section_count = usize::from(read_u16_elf(&caller_bytes, 60).unwrap());
        let relocation_header = (1..section_count)
            .map(|index| elf_section_header(section_offset, section_count, index).unwrap())
            .find(|header| read_u32_elf(&caller_bytes, *header + 4).unwrap() == 4)
            .unwrap();
        let records_offset =
            to_usize_elf(read_u64_elf(&caller_bytes, relocation_header + 24).unwrap()).unwrap();
        let info = read_u64_elf(&caller_bytes, records_offset + 8).unwrap();
        caller_bytes[records_offset..records_offset + 8].copy_from_slice(&0u64.to_le_bytes());
        caller_bytes[records_offset + 8..records_offset + 16]
            .copy_from_slice(&((info & !0xffff_ffff) | 10).to_le_bytes());
        caller_bytes[records_offset + 16..records_offset + 24].copy_from_slice(&0i64.to_le_bytes());
        let caller_bytes = &caller_bytes[..caller.len()];
        let caller_selection = select_x86_64_elf_sections(caller_bytes, &["entry"]).unwrap();
        let caller_sections =
            decode_x86_64_elf_selected_sections(caller_bytes, &caller_selection).unwrap();
        let caller_definitions =
            decode_x86_64_elf_selected_definitions(caller_bytes, &caller_selection).unwrap();
        let caller_relocations =
            decode_x86_64_elf_selected_relocations(caller_bytes, &caller_selection).unwrap();
        assert_eq!(
            caller_relocations.relocations()[0].kind,
            ElfSelectedRelocationKind::Absolute32
        );
        let callee_selection = select_x86_64_elf_sections(callee.bytes(), &["helper"]).unwrap();
        let callee_sections =
            decode_x86_64_elf_selected_sections(callee.bytes(), &callee_selection).unwrap();
        let callee_definitions =
            decode_x86_64_elf_selected_definitions(callee.bytes(), &callee_selection).unwrap();
        let callee_relocations =
            decode_x86_64_elf_selected_relocations(callee.bytes(), &callee_selection).unwrap();
        let objects = [
            ElfSelectedObject {
                sections: &caller_sections,
                definitions: &caller_definitions,
                relocations: &caller_relocations,
            },
            ElfSelectedObject {
                sections: &callee_sections,
                definitions: &callee_definitions,
                relocations: &callee_relocations,
            },
        ];
        let linked =
            link_x86_64_elf_selected_sections::<4096>(&objects, "entry", 0x401000).unwrap();
        let helper_offset = linked
            .layout
            .sections()
            .iter()
            .find(|section| section.input_index == 1)
            .unwrap()
            .offset;
        assert_eq!(
            u32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            u32::try_from(0x401000usize + helper_offset).unwrap()
        );
        assert_eq!(
            link_x86_64_elf_selected_sections::<4096>(&objects, "entry", u64::from(u32::MAX)),
            Err(LinkerError::RelocationOverflow)
        );
    }

    #[test]
    fn selected_elf_coalesces_common_storage_and_prefers_regular_definitions() {
        let empty_section = ElfSelectedSection {
            index: 0,
            name: "",
            kind: ElfSectionKind::Text,
            bytes: &[],
            size: 0,
            alignment: 1,
        };
        let mut caller_sections = ElfSelectedSections {
            sections: [empty_section; MAX_LINK_INPUTS],
            length: 1,
        };
        caller_sections.sections[0] = ElfSelectedSection {
            index: 1,
            name: ".text",
            kind: ElfSectionKind::Text,
            bytes: &[0; 8],
            size: 8,
            alignment: 1,
        };
        let empty_definition = ElfSelectedDefinition {
            name: "",
            section_index: 0,
            offset: 0,
            size: 0,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::Unspecified,
        };
        let mut caller_definitions = ElfSelectedDefinitions {
            definitions: [empty_definition; MAX_LINK_DEFINITIONS],
            length: 1,
        };
        caller_definitions.definitions[0] = ElfSelectedDefinition {
            name: "entry",
            section_index: 1,
            offset: 0,
            size: 8,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::Function,
        };
        let empty_relocation = ElfSelectedRelocation {
            section_index: 0,
            offset: 0,
            kind: ElfSelectedRelocationKind::PcRelative32,
            target: ElfSelectedRelocationTarget::Absolute(0),
            addend: 0,
        };
        let mut caller_relocations = ElfSelectedRelocations {
            relocations: [empty_relocation; MAX_LINK_RELOCATIONS],
            length: 1,
        };
        caller_relocations.relocations[0] = ElfSelectedRelocation {
            section_index: 1,
            offset: 0,
            kind: ElfSelectedRelocationKind::PcRelative32,
            target: ElfSelectedRelocationTarget::Symbol("shared"),
            addend: -4,
        };
        let empty_sections = ElfSelectedSections {
            sections: [empty_section; MAX_LINK_INPUTS],
            length: 0,
        };
        let empty_relocations = ElfSelectedRelocations {
            relocations: [empty_relocation; MAX_LINK_RELOCATIONS],
            length: 0,
        };
        let mut common_small = ElfSelectedDefinitions {
            definitions: [empty_definition; MAX_LINK_DEFINITIONS],
            length: 1,
        };
        common_small.definitions[0] = ElfSelectedDefinition {
            name: "shared",
            section_index: 0xfff2,
            offset: 8,
            size: 8,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::Object,
        };
        let mut common_large = common_small;
        common_large.definitions[0].offset = 32;
        common_large.definitions[0].size = 24;
        let common_objects = [
            ElfSelectedObject {
                sections: &caller_sections,
                definitions: &caller_definitions,
                relocations: &caller_relocations,
            },
            ElfSelectedObject {
                sections: &empty_sections,
                definitions: &common_small,
                relocations: &empty_relocations,
            },
            ElfSelectedObject {
                sections: &empty_sections,
                definitions: &common_large,
                relocations: &empty_relocations,
            },
        ];
        let linked =
            link_x86_64_elf_selected_sections::<8192>(&common_objects, "entry", 0x401000).unwrap();
        assert_eq!(linked.layout.commons().len(), 1);
        assert_eq!(linked.layout.commons()[0].alignment, 32);
        assert_eq!(linked.layout.commons()[0].size, 24);
        assert_eq!(linked.layout.commons()[0].offset, 4096);
        assert_eq!(linked.length, 4096);
        assert_eq!(linked.memory_length, 4120);
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            4092
        );

        let mut strong_sections = ElfSelectedSections {
            sections: [empty_section; MAX_LINK_INPUTS],
            length: 1,
        };
        strong_sections.sections[0] = ElfSelectedSection {
            index: 2,
            name: ".data",
            kind: ElfSectionKind::WritableData,
            bytes: &[7; 8],
            size: 8,
            alignment: 8,
        };
        let mut strong_definition = common_small;
        strong_definition.definitions[0].section_index = 2;
        strong_definition.definitions[0].offset = 0;
        let strong_objects = [
            common_objects[0],
            common_objects[1],
            ElfSelectedObject {
                sections: &strong_sections,
                definitions: &strong_definition,
                relocations: &empty_relocations,
            },
        ];
        let linked =
            link_x86_64_elf_selected_sections::<8192>(&strong_objects, "entry", 0x401000).unwrap();
        assert!(linked.layout.commons().is_empty());
        assert_eq!(linked.memory_length, 4104);
        assert_eq!(&linked.bytes()[4096..4104], &[7; 8]);
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            4092
        );
        assert_eq!(
            validate_elf_common_shape(8, 3),
            Err(LinkerError::UnsupportedElf)
        );

        let mut tls_sections = ElfSelectedSections {
            sections: [empty_section; MAX_LINK_INPUTS],
            length: 2,
        };
        tls_sections.sections[0] = ElfSelectedSection {
            index: 2,
            name: ".tdata.value",
            kind: ElfSectionKind::InitializedTls,
            bytes: &[7; 8],
            size: 8,
            alignment: 8,
        };
        tls_sections.sections[1] = ElfSelectedSection {
            index: 3,
            name: ".tbss.zero",
            kind: ElfSectionKind::ZeroedTls,
            bytes: &[],
            size: 8,
            alignment: 8,
        };
        let mut tls_definitions = ElfSelectedDefinitions {
            definitions: [empty_definition; MAX_LINK_DEFINITIONS],
            length: 1,
        };
        tls_definitions.definitions[0] = ElfSelectedDefinition {
            name: "tls_value",
            section_index: 2,
            offset: 0,
            size: 8,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::ThreadLocal,
        };
        let mut tls_relocations = caller_relocations;
        tls_relocations.relocations[0].kind = ElfSelectedRelocationKind::ThreadPointerOffset32;
        tls_relocations.relocations[0].target = ElfSelectedRelocationTarget::Symbol("tls_value");
        tls_relocations.relocations[0].addend = 0;
        let tls_objects = [
            ElfSelectedObject {
                sections: &caller_sections,
                definitions: &caller_definitions,
                relocations: &tls_relocations,
            },
            ElfSelectedObject {
                sections: &tls_sections,
                definitions: &tls_definitions,
                relocations: &empty_relocations,
            },
        ];
        let linked =
            link_x86_64_elf_selected_sections::<8192>(&tls_objects, "entry", 0x401000).unwrap();
        assert_eq!(linked.layout.tls_offset, 4096);
        assert_eq!(linked.layout.tls_file_length, 8);
        assert_eq!(linked.layout.tls_memory_length, 16);
        assert_eq!(linked.length, 4104);
        assert_eq!(linked.memory_length, 4112);
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            -16
        );
        let executable =
            link_x86_64_elf_selected_executable::<16384, 8192>(&tls_objects, "entry").unwrap();
        assert_eq!(read_u16_elf(executable.bytes(), 56).unwrap(), 4);
        assert_eq!(read_u32_elf(executable.bytes(), 64 + 3 * 56).unwrap(), 7);
    }

    #[test]
    fn selected_elf_places_and_relocates_initializer_arrays() {
        assert_eq!(
            elf_array_section_priority(".preinit_array.50", ElfSectionKind::PreInitializerArray),
            Err(LinkerError::UnsupportedElf)
        );
        assert_eq!(
            elf_array_section_priority(".init_array.65536", ElfSectionKind::InitializerArray),
            Err(LinkerError::UnsupportedElf)
        );
        let empty_section = ElfSelectedSection {
            index: 0,
            name: "",
            kind: ElfSectionKind::Text,
            bytes: &[],
            size: 0,
            alignment: 1,
        };
        let mut sections = ElfSelectedSections {
            sections: [empty_section; MAX_LINK_INPUTS],
            length: 6,
        };
        sections.sections[0] = ElfSelectedSection {
            index: 1,
            name: ".text",
            kind: ElfSectionKind::Text,
            bytes: &[0; 48],
            size: 48,
            alignment: 16,
        };
        sections.sections[1] = ElfSelectedSection {
            index: 2,
            name: ".preinit_array",
            kind: ElfSectionKind::PreInitializerArray,
            bytes: &[0; 8],
            size: 8,
            alignment: 8,
        };
        sections.sections[2] = ElfSelectedSection {
            index: 3,
            name: ".init_array.200",
            kind: ElfSectionKind::InitializerArray,
            bytes: &[0; 8],
            size: 8,
            alignment: 8,
        };
        sections.sections[3] = ElfSelectedSection {
            index: 4,
            name: ".init_array.100",
            kind: ElfSectionKind::InitializerArray,
            bytes: &[0; 8],
            size: 8,
            alignment: 8,
        };
        sections.sections[4] = ElfSelectedSection {
            index: 5,
            name: ".fini_array.100",
            kind: ElfSectionKind::FinalizerArray,
            bytes: &[0; 8],
            size: 8,
            alignment: 8,
        };
        sections.sections[5] = ElfSelectedSection {
            index: 6,
            name: ".fini_array.200",
            kind: ElfSectionKind::FinalizerArray,
            bytes: &[0; 8],
            size: 8,
            alignment: 8,
        };
        let empty_definition = ElfSelectedDefinition {
            name: "",
            section_index: 0,
            offset: 0,
            size: 0,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::Unspecified,
        };
        let mut definitions = ElfSelectedDefinitions {
            definitions: [empty_definition; MAX_LINK_DEFINITIONS],
            length: 3,
        };
        definitions.definitions[0] = ElfSelectedDefinition {
            name: "entry",
            section_index: 1,
            offset: 0,
            size: 48,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Default,
            kind: ElfSelectedSymbolKind::Function,
        };
        definitions.definitions[1] = ElfSelectedDefinition {
            name: "initializer",
            section_index: 1,
            offset: 0,
            size: 48,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Hidden,
            kind: ElfSelectedSymbolKind::Function,
        };
        definitions.definitions[2] = ElfSelectedDefinition {
            name: "__init_array_start",
            section_index: 1,
            offset: 8,
            size: 8,
            binding: ElfSelectedSymbolBinding::Global,
            visibility: ElfSelectedSymbolVisibility::Hidden,
            kind: ElfSelectedSymbolKind::Object,
        };
        let empty_relocation = ElfSelectedRelocation {
            section_index: 0,
            offset: 0,
            kind: ElfSelectedRelocationKind::Absolute64,
            target: ElfSelectedRelocationTarget::Absolute(0),
            addend: 0,
        };
        let mut relocations = ElfSelectedRelocations {
            relocations: [empty_relocation; MAX_LINK_RELOCATIONS],
            length: 11,
        };
        for (relocation, section_index) in
            relocations.relocations[..5].iter_mut().zip([2, 3, 4, 5, 6])
        {
            *relocation = ElfSelectedRelocation {
                section_index,
                offset: 0,
                kind: ElfSelectedRelocationKind::Absolute64,
                target: ElfSelectedRelocationTarget::Symbol("initializer"),
                addend: 0,
            };
        }
        for (index, symbol) in [
            "__preinit_array_start",
            "__preinit_array_end",
            "__init_array_start",
            "__init_array_end",
            "__fini_array_start",
            "__fini_array_end",
        ]
        .into_iter()
        .enumerate()
        {
            relocations.relocations[5 + index] = ElfSelectedRelocation {
                section_index: 1,
                offset: index * 8,
                kind: ElfSelectedRelocationKind::Absolute64,
                target: ElfSelectedRelocationTarget::Symbol(symbol),
                addend: 0,
            };
        }
        let object = [ElfSelectedObject {
            sections: &sections,
            definitions: &definitions,
            relocations: &relocations,
        }];
        let linked = link_x86_64_elf_selected_sections::<8192>(&object, "entry", 0x401000).unwrap();
        assert_eq!(linked.layout.writable_offset, 4096);
        assert_eq!(linked.layout.preinitializer_start, 4096);
        assert_eq!(linked.layout.preinitializer_end, 4104);
        assert_eq!(linked.layout.initializer_start, 4104);
        assert_eq!(linked.layout.initializer_end, 4120);
        assert_eq!(linked.layout.finalizer_start, 4120);
        assert_eq!(linked.layout.finalizer_end, 4136);
        assert_eq!(linked.layout.file_length, 4136);
        assert_eq!(linked.layout.memory_length, 4136);
        assert_eq!(
            linked
                .layout
                .sections()
                .iter()
                .map(|section| section.section_index)
                .collect::<std::vec::Vec<_>>(),
            [1, 2, 4, 3, 5, 6]
        );
        for offset in (4096..4136).step_by(8) {
            assert_eq!(
                u64::from_le_bytes(linked.bytes()[offset..offset + 8].try_into().unwrap()),
                0x401000
            );
        }
        assert_eq!(
            (0..6)
                .map(|index| u64::from_le_bytes(
                    linked.bytes()[index * 8..index * 8 + 8].try_into().unwrap()
                ))
                .collect::<std::vec::Vec<_>>(),
            [0x402000, 0x402008, 0x401008, 0x402018, 0x402018, 0x402028]
        );
    }

    #[test]
    fn selected_elf_decodes_and_applies_signed_absolute_32_relocations() {
        let caller_code = MachineCode::<8>::from_bytes_for_test(&[0, 0, 0, 0, 0xc3]);
        let caller = emit_elf64_x86_64_with_relocation::<1024, 8>(
            "entry",
            &caller_code,
            X86_64PcRelativeRelocation {
                offset: 1,
                symbol: "helper",
                kind: X86_64PcRelativeRelocationKind::Branch,
            },
        )
        .unwrap();
        let callee_code = MachineCode::<8>::from_bytes_for_test(&[0xc3]);
        let callee = emit_elf64_x86_64::<512, 8>("helper", &callee_code).unwrap();
        let mut caller_bytes = [0u8; 1024];
        caller_bytes[..caller.len()].copy_from_slice(caller.bytes());
        let section_offset = to_usize_elf(read_u64_elf(&caller_bytes, 40).unwrap()).unwrap();
        let section_count = usize::from(read_u16_elf(&caller_bytes, 60).unwrap());
        let relocation_header = (1..section_count)
            .map(|index| elf_section_header(section_offset, section_count, index).unwrap())
            .find(|header| read_u32_elf(&caller_bytes, *header + 4).unwrap() == 4)
            .unwrap();
        let records_offset =
            to_usize_elf(read_u64_elf(&caller_bytes, relocation_header + 24).unwrap()).unwrap();
        let info = read_u64_elf(&caller_bytes, records_offset + 8).unwrap();
        caller_bytes[records_offset..records_offset + 8].copy_from_slice(&0u64.to_le_bytes());
        caller_bytes[records_offset + 8..records_offset + 16]
            .copy_from_slice(&((info & !0xffff_ffff) | 11).to_le_bytes());
        caller_bytes[records_offset + 16..records_offset + 24].copy_from_slice(&0i64.to_le_bytes());
        let caller_bytes = &caller_bytes[..caller.len()];
        let caller_selection = select_x86_64_elf_sections(caller_bytes, &["entry"]).unwrap();
        let caller_sections =
            decode_x86_64_elf_selected_sections(caller_bytes, &caller_selection).unwrap();
        let caller_definitions =
            decode_x86_64_elf_selected_definitions(caller_bytes, &caller_selection).unwrap();
        let caller_relocations =
            decode_x86_64_elf_selected_relocations(caller_bytes, &caller_selection).unwrap();
        assert_eq!(
            caller_relocations.relocations()[0].kind,
            ElfSelectedRelocationKind::SignedAbsolute32
        );
        let callee_selection = select_x86_64_elf_sections(callee.bytes(), &["helper"]).unwrap();
        let callee_sections =
            decode_x86_64_elf_selected_sections(callee.bytes(), &callee_selection).unwrap();
        let callee_definitions =
            decode_x86_64_elf_selected_definitions(callee.bytes(), &callee_selection).unwrap();
        let callee_relocations =
            decode_x86_64_elf_selected_relocations(callee.bytes(), &callee_selection).unwrap();
        let objects = [
            ElfSelectedObject {
                sections: &caller_sections,
                definitions: &caller_definitions,
                relocations: &caller_relocations,
            },
            ElfSelectedObject {
                sections: &callee_sections,
                definitions: &callee_definitions,
                relocations: &callee_relocations,
            },
        ];
        let linked =
            link_x86_64_elf_selected_sections::<4096>(&objects, "entry", 0x401000).unwrap();
        let helper_offset = linked
            .layout
            .sections()
            .iter()
            .find(|section| section.input_index == 1)
            .unwrap()
            .offset;
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            i32::try_from(0x401000usize + helper_offset).unwrap()
        );
        assert_eq!(
            link_x86_64_elf_selected_sections::<4096>(&objects, "entry", i32::MAX as u64),
            Err(LinkerError::RelocationOverflow)
        );
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
            target: LinkDefinitionTarget::Text(0),
        }; MAX_LINK_DEFINITIONS];
        let decoded =
            decode_x86_64_elf_with_definitions(&bytes, &mut relocations, &mut definitions).unwrap();
        assert_eq!(
            decoded.additional_definitions,
            &[LinkDefinition {
                symbol: "second",
                target: LinkDefinitionTarget::Text(6),
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
            symbol_target: LinkDefinitionTarget::Text(0),
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

    #[test]
    fn emits_and_relocates_bounded_elf_unwind_data() {
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let mut unwind_bytes = [0u8; 48];
        unwind_bytes[..4].copy_from_slice(&20u32.to_le_bytes());
        unwind_bytes[24..28].copy_from_slice(&16u32.to_le_bytes());
        unwind_bytes[28..32].copy_from_slice(&28u32.to_le_bytes());
        let unwind_relocations = [ElfUnwindRelocation {
            offset: 32,
            target_text_offset: 0,
            addend: 0,
        }];
        let unwind = [ElfUnwindData {
            bytes: &unwind_bytes,
            relocations: &unwind_relocations,
        }];
        let elf = link_x86_64_elf_executable_with_unwind::<16384, 8192>(&[input], &unwind, "entry")
            .unwrap();
        assert_eq!(read_u16_elf(elf.bytes(), 56).unwrap(), 4);
        assert_eq!(elf.bytes().len(), 0x2048);
        assert_eq!(&elf.bytes()[0x2000..0x2004], &[1, 0x1b, 3, 0x3b]);
        assert_eq!(read_u32_elf(elf.bytes(), 0x2008).unwrap(), 1);
        assert_eq!(read_u32_elf(elf.bytes(), 232).unwrap(), 0x6474_e550);
        assert_eq!(
            i32::from_le_bytes(elf.bytes()[0x2038..0x203c].try_into().unwrap()),
            -0x1038
        );

        let invalid_relocations = [ElfUnwindRelocation {
            offset: 45,
            ..unwind_relocations[0]
        }];
        let invalid = [ElfUnwindData {
            bytes: &unwind_bytes,
            relocations: &invalid_relocations,
        }];
        assert_eq!(
            link_x86_64_elf_executable_with_unwind::<16384, 8192>(&[input], &invalid, "entry"),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn emits_initialized_and_zeroed_elf_writable_data() {
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 8],
            readonly_data: &[],
            relocations: &[],
        };
        let references = [
            ElfWritableReference {
                text_offset: 0,
                target: ElfWritableTarget::Initialized(0),
                addend: 0,
            },
            ElfWritableReference {
                text_offset: 4,
                target: ElfWritableTarget::Zeroed(0),
                addend: 0,
            },
        ];
        let writable = [ElfWritableData {
            initialized: &[42],
            initialized_alignment: 1,
            zeroed_size: 8,
            zeroed_alignment: 1,
            references: &references,
            absolute_relocations: &[],
        }];
        let elf = link_x86_64_elf_executable_with_unwind_and_writable::<16384, 8192>(
            &[input],
            &[],
            &writable,
            "entry",
        )
        .unwrap();
        assert_eq!(read_u16_elf(elf.bytes(), 56).unwrap(), 3);
        assert_eq!(read_u32_elf(elf.bytes(), 176 + 4).unwrap(), 6);
        assert_eq!(read_u64_elf(elf.bytes(), 176 + 32).unwrap(), 1);
        assert_eq!(read_u64_elf(elf.bytes(), 176 + 40).unwrap(), 0x18);
        assert_eq!(elf.bytes().len(), 0x2001);
        assert_eq!(elf.bytes()[0x2000], 42);
        assert_eq!(
            i32::from_le_bytes(elf.bytes()[0x1000..0x1004].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            i32::from_le_bytes(elf.bytes()[0x1004..0x1008].try_into().unwrap()),
            0x100c
        );

        let invalid_references = [ElfWritableReference {
            target: ElfWritableTarget::Zeroed(9),
            ..references[0]
        }];
        let invalid = [ElfWritableData {
            references: &invalid_references,
            ..writable[0]
        }];
        assert_eq!(
            link_x86_64_elf_executable_with_unwind_and_writable::<16384, 8192>(
                &[input],
                &[],
                &invalid,
                "entry"
            ),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn applies_bounded_absolute_relocations_in_elf_writable_data() {
        let required = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::RequiredSymbol("helper"),
            addend: 0,
        }];
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[42],
            relocations: &required,
        };
        let helper = LinkInput {
            symbol: "helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let absolute_relocations = [
            ElfWritableAbsoluteRelocation {
                offset: 0,
                target: ElfWritableAbsoluteTarget::ReadonlyData(0),
                addend: 0,
            },
            ElfWritableAbsoluteRelocation {
                offset: 8,
                target: ElfWritableAbsoluteTarget::Initialized(16),
                addend: 0,
            },
            ElfWritableAbsoluteRelocation {
                offset: 16,
                target: ElfWritableAbsoluteTarget::Zeroed(0),
                addend: 0,
            },
            ElfWritableAbsoluteRelocation {
                offset: 24,
                target: ElfWritableAbsoluteTarget::Symbol("helper"),
                addend: 0,
            },
        ];
        let writable = [
            ElfWritableData {
                initialized: &[0; 32],
                initialized_alignment: 8,
                zeroed_size: 8,
                zeroed_alignment: 8,
                references: &[],
                absolute_relocations: &absolute_relocations,
            },
            ElfWritableData {
                initialized: &[],
                initialized_alignment: 1,
                zeroed_size: 0,
                zeroed_alignment: 1,
                references: &[],
                absolute_relocations: &[],
            },
        ];
        let elf = link_x86_64_elf_executable_with_unwind_and_writable::<16384, 8192>(
            &[input, helper],
            &[
                ElfUnwindData {
                    bytes: &[],
                    relocations: &[],
                },
                ElfUnwindData {
                    bytes: &[],
                    relocations: &[],
                },
            ],
            &writable,
            "entry",
        )
        .unwrap();
        assert_eq!(read_u64_elf(elf.bytes(), 0x3000).unwrap(), 0x402000);
        assert_eq!(read_u64_elf(elf.bytes(), 0x3008).unwrap(), 0x403010);
        assert_eq!(read_u64_elf(elf.bytes(), 0x3010).unwrap(), 0x403020);
        assert_eq!(read_u64_elf(elf.bytes(), 0x3018).unwrap(), 0x401010);

        let invalid_relocations = [ElfWritableAbsoluteRelocation {
            offset: 25,
            ..absolute_relocations[0]
        }];
        let invalid = [
            ElfWritableData {
                absolute_relocations: &invalid_relocations,
                ..writable[0]
            },
            writable[1],
        ];
        assert_eq!(
            link_x86_64_elf_executable_with_unwind_and_writable::<16384, 8192>(
                &[input, helper],
                &[
                    ElfUnwindData {
                        bytes: &[],
                        relocations: &[],
                    },
                    ElfUnwindData {
                        bytes: &[],
                        relocations: &[],
                    },
                ],
                &invalid,
                "entry"
            ),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[test]
    fn bounds_zero_sized_elf_readonly_targets() {
        let mut object = [0u8; 128];
        object[64 + 48..64 + 56].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(elf_readonly_offset(&object, 64, 1, 0, None, 0), Ok(0));
        assert_eq!(
            elf_readonly_offset(&object, 64, 1, 0, None, 1),
            Err(LinkerError::InvalidRelocationOffset)
        );
        object[64 + 48..64 + 56].copy_from_slice(&32u64.to_le_bytes());
        assert_eq!(
            elf_readonly_offset(&object, 64, 1, 0, None, 0),
            Err(LinkerError::InvalidRelocationOffset)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_elf_executes_on_the_controlled_linux_host() {
        use std::os::unix::fs::PermissionsExt;

        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
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

        let code = MachineCode::<16>::from_bytes_for_test(&[
            0xbf, 42, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
        ]);
        let object = emit_elf64_x86_64::<512, 16>("entry", &code).unwrap();
        let selection = select_x86_64_elf_sections(object.bytes(), &["entry"]).unwrap();
        let sections = decode_x86_64_elf_selected_sections(object.bytes(), &selection).unwrap();
        let definitions =
            decode_x86_64_elf_selected_definitions(object.bytes(), &selection).unwrap();
        let relocations =
            decode_x86_64_elf_selected_relocations(object.bytes(), &selection).unwrap();
        let objects = [ElfSelectedObject {
            sections: &sections,
            definitions: &definitions,
            relocations: &relocations,
        }];
        let selected =
            link_x86_64_elf_selected_executable::<8192, 4096>(&objects, "entry").unwrap();
        let selected_path = std::env::temp_dir().join(std::format!(
            "mrml-selected-linker-elf-{}",
            std::process::id()
        ));
        std::fs::write(&selected_path, selected.bytes()).unwrap();
        std::fs::set_permissions(&selected_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let selected_status = std::process::Command::new(&selected_path).status().unwrap();
        std::fs::remove_file(selected_path).unwrap();
        assert_eq!(selected_status.code(), Some(42));
    }
}
