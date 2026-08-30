#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate std;

use mrml_error::{Result, anyhow};
use mrml_runtime::{
    MappedFile, Text, Vector, canonical_path, join_path, mrml_println as println, parent_path,
};
use mrml_rustc::{
    CodegenOptions, CoffObjectSymbolKind, CoffSectionIdentity, CoffTextComdatSelection, ElfSelectedDefinitions,
    ElfSelectedObject, ElfSelectedRelocations, ElfSelectedSections, LinkDefinition,
    LinkDefinitionTarget, LinkInput, LinkRelocation, LinkRelocationTarget, MAX_ARCHIVE_MEMBERS,
    MAX_ARCHIVE_SYMBOLS, MAX_LINK_DEFINITIONS, MAX_LINK_FRAGMENTS, MAX_LINK_INPUTS,
    MAX_LINK_RELOCATIONS, MAX_PE_READONLY_RELOCATIONS, MAX_PE_RUNTIME_FUNCTIONS, ObjectFormat,
    PeReadonlyAbsoluteRelocation, PeRuntimeFunction, PeWritableData, PeWritableRelocation,
    PeWritableRelocationTarget,
    TargetLayout, compile_source_function_with_options, decode_unix_archive,
    decode_x86_64_coff_readonly_absolute_relocations_with_section_identities_from_inventory,
    decode_x86_64_coff_short_import,
    decode_x86_64_coff_runtime_functions_with_section_identities,
    decode_x86_64_coff_section_identity_readonly_fragment,
    decode_x86_64_coff_text_fragment_with_section_identities_from_inventory,
    decode_x86_64_coff_writable_data_fragment_with_section_identities,
    decode_x86_64_elf_selected_definitions_from_sections,
    decode_x86_64_elf_selected_relocations_from_sections, decode_x86_64_elf_selected_sections,
    decode_x86_64_elf_with_definitions, inventory_x86_64_coff_comdat_sections,
    inventory_x86_64_coff_symbols, inventory_x86_64_elf_symbols,
    link_x86_64_elf_selected_executable, link_x86_64_pe_with_data_unwind_and_readonly_relocations,
    select_ordered_static_link_members, select_x86_64_elf_link_sections_detailed,
    x86_64_coff_section_identity_readonly_fragment_count,
    x86_64_coff_short_import,
    x86_64_coff_text_fragment_comdat_selection_from_inventory, x86_64_coff_text_fragment_count,
    x86_64_coff_writable_section_count,
};

#[cfg_attr(test, allow(dead_code))]
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_OBJECT_BYTES: usize = 4096;
#[cfg_attr(test, allow(dead_code))]
const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_CODE_BYTES: usize = 4 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_ITEMS: usize = 64;
#[cfg_attr(test, allow(dead_code))]
const MAX_PARAMETERS: usize = 16;
#[cfg_attr(test, allow(dead_code))]
const MAX_CONSTANTS: usize = 64;
#[cfg_attr(test, allow(dead_code))]
const MAX_EXPRESSION_NODES: usize = 256;
#[cfg_attr(test, allow(dead_code))]
const MAX_LINKED_BYTES: usize = 2 * 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_EXECUTABLE_BYTES: usize = 3 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmitKind {
    Object(ObjectFormat),
    Pe,
    ElfExecutable,
}

struct LinkObjectRefs<'a> {
    bytes: Vector<&'a [u8]>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
}

enum LinkFile {
    Mapped(MappedFile),
    Buffered(Vector<u8>),
}

struct SelectedThinMember {
    member_index: usize,
    file: MappedFile,
}

impl AsRef<[u8]> for LinkFile {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Mapped(file) => file.as_ref(),
            Self::Buffered(bytes) => bytes,
        }
    }
}

struct DecodedLinkInputs<'data, 'relocations, 'definitions> {
    inputs: Vector<LinkInput<'data, 'relocations, 'definitions>>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
    source_object: Vector<usize>,
    comdat_selection: Vector<CoffTextComdatSelection>,
}

struct SelectedLinkInputs<'data, 'relocations, 'definitions> {
    inputs: Vector<LinkInput<'data, 'relocations, 'definitions>>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
    source_object: Vector<usize>,
}

// The fixed-capacity parser intentionally keeps its arenas on the stack. The
// Windows PE default is too small for debug builds at the public driver limits.
#[cfg(windows)]
#[used]
#[unsafe(link_section = ".drectve")]
static WINDOWS_STACK_RESERVE: [u8; 16] = *b"/STACK:16777216 ";

#[cfg_attr(test, allow(dead_code))]
fn application_main() -> Result<()> {
    let arguments = mrml_runtime::command_arguments();
    if arguments.len() >= 7
        && arguments[1] == "--link-coff"
        && arguments[arguments.len() - 4] == "--entry"
        && arguments[arguments.len() - 2] == "-o"
    {
        let output = &arguments[arguments.len() - 1];
        if mrml_runtime::path_exists(output) {
            return Err(anyhow!("refusing to overwrite compiler output"));
        }
        let objects = read_link_objects(
            &arguments[2..arguments.len() - 4],
            ObjectFormat::Coff,
            &arguments[arguments.len() - 3],
        )?;
        let object_refs = link_object_refs(
            &objects,
            ObjectFormat::Coff,
            &arguments[arguments.len() - 3],
        )?;
        return write_linked_pe(
            &object_refs.bytes,
            &object_refs.archive_group,
            &object_refs.archive_member,
            &arguments[arguments.len() - 3],
            output,
        );
    }
    if arguments.len() >= 7
        && arguments[1] == "--link-elf"
        && arguments[arguments.len() - 4] == "--entry"
        && arguments[arguments.len() - 2] == "-o"
    {
        let output = &arguments[arguments.len() - 1];
        if mrml_runtime::path_exists(output) {
            return Err(anyhow!("refusing to overwrite compiler output"));
        }
        let objects = read_link_objects(
            &arguments[2..arguments.len() - 4],
            ObjectFormat::Elf64,
            &arguments[arguments.len() - 3],
        )?;
        let object_refs = link_object_refs(
            &objects,
            ObjectFormat::Elf64,
            &arguments[arguments.len() - 3],
        )?;
        return write_linked_elf(
            &object_refs.bytes,
            &object_refs.archive_group,
            &object_refs.archive_member,
            &arguments[arguments.len() - 3],
            output,
        );
    }
    if arguments.len() < 8 || arguments[1] != "--emit" || arguments[3] != "--function" {
        return Err(anyhow!(
            "usage: mrml-rustc --emit elf64|coff|pe|elf-executable --function NAME [-C overflow-checks=yes|no] INPUT -o OUTPUT; or mrml-rustc --link-coff|--link-elf INPUT... --entry NAME -o OUTPUT"
        ));
    }
    let emit = parse_emit_kind(&arguments[2])?;
    let function = &arguments[4];
    let (options, input, output) = match arguments.len() {
        8 if arguments[6] == "-o" => (CodegenOptions::CHECKED, &arguments[5], &arguments[7]),
        9 if arguments[7] == "-o" => {
            let option = arguments[5]
                .strip_prefix("-C")
                .ok_or_else(|| anyhow!("expected -Coverflow-checks=yes|no"))?;
            (parse_codegen_options(option)?, &arguments[6], &arguments[8])
        }
        10 if arguments[5] == "-C" && arguments[8] == "-o" => (
            parse_codegen_options(&arguments[6])?,
            &arguments[7],
            &arguments[9],
        ),
        _ => {
            return Err(anyhow!(
                "usage: mrml-rustc --emit elf64|coff|pe|elf-executable --function NAME [-C overflow-checks=yes|no] INPUT -o OUTPUT; or mrml-rustc --link-coff|--link-elf INPUT... --entry NAME -o OUTPUT"
            ));
        }
    };
    if mrml_runtime::path_exists(output) {
        return Err(anyhow!("refusing to overwrite compiler output"));
    }
    let source = mrml_runtime::read_file_text_bounded(input, MAX_SOURCE_BYTES)?;
    let object_format = match emit {
        EmitKind::Object(format) => format,
        EmitKind::Pe => ObjectFormat::Coff,
        EmitKind::ElfExecutable => ObjectFormat::Elf64,
    };
    let object = compile_source_function_with_options::<
        MAX_OBJECT_BYTES,
        MAX_CODE_BYTES,
        MAX_ITEMS,
        MAX_PARAMETERS,
        MAX_CONSTANTS,
        MAX_EXPRESSION_NODES,
    >(
        &source,
        function,
        object_format,
        TargetLayout::X86_64,
        options,
    )
    .map_err(mrml_error::message)?;
    match emit {
        EmitKind::Object(_) => {
            mrml_runtime::write_file(output, object.bytes())?;
            println!(
                "compiled {} to {} deterministic object bytes",
                function,
                object.len()
            );
        }
        EmitKind::Pe => {
            write_linked_pe(&[object.bytes()], &[0], &[0], function, output)?;
        }
        EmitKind::ElfExecutable => {
            write_linked_elf(&[object.bytes()], &[0], &[0], function, output)?;
        }
    }
    Ok(())
}

fn read_link_objects(
    paths: &[Text],
    format: ObjectFormat,
    entry: &str,
) -> Result<Vector<LinkFile>> {
    if paths.is_empty() || paths.len() > MAX_LINK_INPUTS {
        return Err(anyhow!("link input count must be between 1 and 256"));
    }
    let mut objects = Vector::with_capacity(paths.len())
        .map_err(|_| anyhow!("could not allocate link input list"))?;
    let mut referenced = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    let mut defined = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate defined-symbol list"))?;
    referenced
        .try_push(Text::from(entry))
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    let mut thin_index_selection_safe = true;
    for path in paths {
        let file = MappedFile::open_bounded(path, MAX_ARCHIVE_BYTES)?;
        if file.as_ref().get(..8) == Some(b"!<thin>\n") {
            let archive = decode_unix_archive(file.as_ref()).map_err(mrml_error::message)?;
            let parent = canonical_path(
                parent_path(path)
                    .ok_or_else(|| anyhow!("thin archive path has no parent directory"))?,
            )?;
            let mut materialized = Vector::with_capacity(MAX_ARCHIVE_BYTES)
                .map_err(|_| anyhow!("could not allocate thin archive materialization"))?;
            materialized
                .try_extend_from_slice(b"!<arch>\n")
                .map_err(|_| anyhow!("thin archive materialization exceeds 64 MiB"))?;
            let mut selected = [false; MAX_ARCHIVE_MEMBERS];
            let mut selected_files = Vector::with_capacity(MAX_LINK_INPUTS)
                .map_err(|_| anyhow!("could not allocate selected thin-member list"))?;
            if archive.symbols().is_empty() || !thin_index_selection_safe {
                selected[..archive.members().len()].fill(true);
                thin_index_selection_safe = false;
            } else {
                let mut reference_cursor = 0usize;
                while reference_cursor < referenced.len() {
                    let symbol = &referenced[reference_cursor];
                    reference_cursor += 1;
                    if defined.iter().any(|definition| definition == symbol) {
                        continue;
                    }
                    let Some(candidate) = archive.symbols().iter().find(|candidate| {
                        candidate.symbol == symbol.as_str() && !selected[candidate.member_index]
                    }) else {
                        continue;
                    };
                    selected[candidate.member_index] = true;
                    let member = &archive.members()[candidate.member_index];
                    let member_file = open_thin_archive_member(&parent, member.name)?;
                    scan_link_object_symbols_owned(
                        member_file.as_ref(),
                        format,
                        &mut referenced,
                        &mut defined,
                    )?;
                    if !defined
                        .iter()
                        .any(|definition| definition.as_str() == candidate.symbol)
                    {
                        return Err(anyhow!(
                            "thin archive symbol index does not match its object member"
                        ));
                    }
                    selected_files
                        .try_push(SelectedThinMember {
                            member_index: candidate.member_index,
                            file: member_file,
                        })
                        .map_err(|_| anyhow!("selected thin-member count exceeds 256"))?;
                }
            }
            for (member_index, member) in archive.members().iter().enumerate() {
                if !member.external {
                    return Err(anyhow!("thin archive contains an embedded object member"));
                }
                if !selected[member_index] {
                    append_materialized_archive_member(&mut materialized, "lib.rmeta", &[])?;
                    continue;
                }
                let selected_file = selected_files
                    .iter()
                    .find(|selected| selected.member_index == member_index);
                let eager_file;
                let member_bytes = if let Some(selected_file) = selected_file {
                    selected_file.file.as_ref()
                } else {
                    eager_file = open_thin_archive_member(&parent, member.name)?;
                    eager_file.as_ref()
                };
                append_materialized_archive_member(&mut materialized, member.name, member_bytes)?;
            }
            objects
                .try_push(LinkFile::Buffered(materialized))
                .map_err(|_| anyhow!("could not allocate link input list"))?;
        } else {
            if file.as_ref().get(..8) == Some(b"!<arch>\n") {
                thin_index_selection_safe = false;
            } else if thin_index_selection_safe {
                scan_link_object_symbols_owned(
                    file.as_ref(),
                    format,
                    &mut referenced,
                    &mut defined,
                )?;
            }
            objects
                .try_push(LinkFile::Mapped(file))
                .map_err(|_| anyhow!("could not allocate link input list"))?;
        }
    }
    Ok(objects)
}

fn open_thin_archive_member(parent: &Text, name: &str) -> Result<MappedFile> {
    let member_path = canonical_path(&join_path(parent, name))?;
    let relative = member_path
        .strip_prefix(parent.as_str())
        .filter(|relative| relative.starts_with('/') || relative.starts_with('\\'))
        .ok_or_else(|| anyhow!("thin archive member escapes its archive directory"))?;
    if relative.len() == 1 {
        return Err(anyhow!(
            "thin archive member resolves to its archive directory"
        ));
    }
    Ok(MappedFile::open_bounded(&member_path, MAX_ARCHIVE_BYTES)?)
}

fn append_materialized_archive_member(
    archive: &mut Vector<u8>,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    let stored_size = name
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| anyhow!("thin archive member size overflow"))?;
    let mut header = [b' '; 60];
    header[..3].copy_from_slice(b"#1/");
    write_archive_decimal(&mut header[3..16], name.len())?;
    write_archive_decimal(&mut header[48..58], stored_size)?;
    header[58..60].copy_from_slice(b"`\n");
    archive
        .try_extend_from_slice(&header)
        .and_then(|_| archive.try_extend_from_slice(name.as_bytes()))
        .and_then(|_| archive.try_extend_from_slice(bytes))
        .map_err(|_| anyhow!("thin archive materialization exceeds 64 MiB"))?;
    if stored_size & 1 != 0 {
        archive
            .try_push(b'\n')
            .map_err(|_| anyhow!("thin archive materialization exceeds 64 MiB"))?;
    }
    Ok(())
}

fn write_archive_decimal(field: &mut [u8], mut value: usize) -> Result<()> {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(value % 10).map_err(|_| anyhow!("decimal overflow"))?;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let encoded = &digits[start..];
    if encoded.len() > field.len() {
        return Err(anyhow!("archive decimal field overflow"));
    }
    field[..encoded.len()].copy_from_slice(encoded);
    Ok(())
}

fn link_object_refs<'a, T: AsRef<[u8]>>(
    objects: &'a [T],
    format: ObjectFormat,
    entry: &'a str,
) -> Result<LinkObjectRefs<'a>> {
    let mut refs: Vector<&'a [u8]> = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link input reference list"))?;
    let mut archive_group = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link input origin list"))?;
    let mut archive_member = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link member origin list"))?;
    if !objects
        .iter()
        .any(|object| object.as_ref().get(..8) == Some(b"!<arch>\n"))
    {
        for object in objects {
            refs.try_push(object.as_ref())
                .map_err(|_| anyhow!("could not allocate link input reference list"))?;
            archive_group
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate link input origin list"))?;
            archive_member
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate link member origin list"))?;
        }
        if refs.is_empty() {
            return Err(anyhow!("link input list contains no object members"));
        }
        return Ok(LinkObjectRefs {
            bytes: refs,
            archive_group,
            archive_member,
        });
    }
    let mut referenced = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    let mut defined = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate defined-symbol list"))?;
    referenced
        .try_push(entry)
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    let mut next_archive_group = 1u16;
    let mut indexed_selection_safe = true;
    let mut indexed_selection_initialized = false;
    for object in objects {
        let object = object.as_ref();
        if object.get(..8) == Some(b"!<arch>\n") {
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            let mut selected = [false; MAX_ARCHIVE_MEMBERS];
            if archive.symbols().is_empty() || !indexed_selection_safe {
                selected[..archive.members().len()].fill(true);
                indexed_selection_safe = false;
            } else {
                if !indexed_selection_initialized {
                    for prior in &refs {
                        scan_link_object_symbols(prior, format, &mut referenced, &mut defined)?;
                    }
                    indexed_selection_initialized = true;
                }
                let mut reference_cursor = 0usize;
                while reference_cursor < referenced.len() {
                    let symbol = referenced[reference_cursor];
                    reference_cursor += 1;
                    if defined.iter().any(|defined| *defined == symbol) {
                        continue;
                    }
                    let Some(candidate) = archive.symbols().iter().find(|candidate| {
                        candidate.symbol == symbol && !selected[candidate.member_index]
                    }) else {
                        continue;
                    };
                    selected[candidate.member_index] = true;
                    scan_link_object_symbols(
                        archive.members()[candidate.member_index].bytes,
                        format,
                        &mut referenced,
                        &mut defined,
                    )
                    .map_err(|error| {
                        anyhow!(
                            "archive group {} member {} ({}) symbol inventory: {}",
                            next_archive_group,
                            candidate.member_index + 1,
                            archive.members()[candidate.member_index].name,
                            error
                        )
                    })?;
                    if !defined.iter().any(|defined| *defined == candidate.symbol) {
                        return Err(anyhow!(
                            "archive symbol index does not match its object member"
                        ));
                    }
                }
            }
            for (member_index, member) in archive.members().iter().enumerate() {
                if member.name == "lib.rmeta" || member.name == "lib.rmeta-link" {
                    continue;
                }
                if !selected[member_index] {
                    continue;
                }
                if refs.len() == MAX_LINK_INPUTS {
                    return Err(anyhow!("expanded link input count exceeds 256"));
                }
                refs.try_push(member.bytes)
                    .map_err(|_| anyhow!("could not allocate link input reference list"))?;
                archive_group
                    .try_push(next_archive_group)
                    .map_err(|_| anyhow!("could not allocate link input origin list"))?;
                archive_member
                    .try_push(
                        u16::try_from(member_index + 1)
                            .map_err(|_| anyhow!("archive member identity overflow"))?,
                    )
                    .map_err(|_| anyhow!("could not allocate link member origin list"))?;
            }
            next_archive_group = next_archive_group
                .checked_add(1)
                .ok_or_else(|| anyhow!("archive group identity overflow"))?;
        } else {
            refs.try_push(&object[..])
                .map_err(|_| anyhow!("could not allocate link input reference list"))?;
            archive_group
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate link input origin list"))?;
            archive_member
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate link member origin list"))?;
            if indexed_selection_safe && indexed_selection_initialized {
                scan_link_object_symbols(object, format, &mut referenced, &mut defined)?;
            }
        }
    }
    if refs.is_empty() {
        return Err(anyhow!("link input list contains no object members"));
    }
    Ok(LinkObjectRefs {
        bytes: refs,
        archive_group,
        archive_member,
    })
}

fn scan_link_object_symbols<'a>(
    object: &'a [u8],
    format: ObjectFormat,
    referenced: &mut Vector<&'a str>,
    defined: &mut Vector<&'a str>,
) -> Result<()> {
    if format == ObjectFormat::Elf64 {
        let inventory = inventory_x86_64_elf_symbols(object)
            .map_err(|error| anyhow!("could not inventory ELF symbols: {}", error))?;
        for definition in inventory.definitions() {
            if !defined
                .iter()
                .any(|existing| *existing == definition.symbol)
            {
                defined
                    .try_push(definition.symbol)
                    .map_err(|_| anyhow!("defined-symbol capacity exceeded"))?;
            }
        }
        for symbol in inventory.references() {
            if !referenced.iter().any(|existing| existing == symbol) {
                referenced
                    .try_push(symbol)
                    .map_err(|_| anyhow!("referenced-symbol capacity exceeded"))?;
            }
        }
        return Ok(());
    }
    let inventory = inventory_x86_64_coff_symbols(object)
        .map_err(|error| anyhow!("could not inventory COFF symbols: {}", error))?;
    for symbol in inventory.symbols() {
        let symbol = symbol.map_err(|error| anyhow!("could not read COFF symbol: {}", error))?;
        match symbol.kind {
            CoffObjectSymbolKind::Definition => {
                if !defined.iter().any(|existing| *existing == symbol.name) {
                    defined
                        .try_push(symbol.name)
                        .map_err(|_| anyhow!("defined-symbol capacity exceeded"))?;
                }
            }
            CoffObjectSymbolKind::Reference => {
                if !referenced.iter().any(|existing| *existing == symbol.name) {
                    referenced
                        .try_push(symbol.name)
                        .map_err(|_| anyhow!("referenced-symbol capacity exceeded"))?;
                }
            }
        }
    }
    Ok(())
}

fn scan_link_object_symbols_owned(
    object: &[u8],
    format: ObjectFormat,
    referenced: &mut Vector<Text>,
    defined: &mut Vector<Text>,
) -> Result<()> {
    if format == ObjectFormat::Elf64 {
        let inventory = inventory_x86_64_elf_symbols(object)
            .map_err(|error| anyhow!("could not inventory ELF symbols: {}", error))?;
        for definition in inventory.definitions() {
            push_owned_symbol(
                defined,
                definition.symbol,
                "defined-symbol capacity exceeded",
            )?;
        }
        for symbol in inventory.references() {
            push_owned_symbol(referenced, symbol, "referenced-symbol capacity exceeded")?;
        }
        return Ok(());
    }
    let inventory = inventory_x86_64_coff_symbols(object)
        .map_err(|error| anyhow!("could not inventory COFF symbols: {}", error))?;
    for symbol in inventory.symbols() {
        let symbol = symbol.map_err(|error| anyhow!("could not read COFF symbol: {}", error))?;
        match symbol.kind {
            CoffObjectSymbolKind::Definition => {
                push_owned_symbol(defined, symbol.name, "defined-symbol capacity exceeded")?;
            }
            CoffObjectSymbolKind::Reference => push_owned_symbol(
                referenced,
                symbol.name,
                "referenced-symbol capacity exceeded",
            )?,
        }
    }
    Ok(())
}

fn push_owned_symbol(symbols: &mut Vector<Text>, symbol: &str, capacity_error: &str) -> Result<()> {
    if !symbols.iter().any(|existing| existing.as_str() == symbol) {
        symbols
            .try_push(Text::from(symbol))
            .map_err(|_| anyhow!(capacity_error))?;
    }
    Ok(())
}

fn decode_link_inputs<'data, 'relocations, 'definitions>(
    objects: &[&'data [u8]],
    object_archive_group: &[u16],
    object_archive_member: &[u16],
    format: ObjectFormat,
    relocation_arenas: &'relocations mut [[LinkRelocation<'data>; MAX_LINK_RELOCATIONS]],
    definition_arenas: &'definitions mut [[LinkDefinition<'data>; MAX_LINK_DEFINITIONS]],
) -> Result<DecodedLinkInputs<'data, 'relocations, 'definitions>> {
    if objects.len() != object_archive_group.len() || objects.len() != object_archive_member.len() {
        return Err(anyhow!("link input origin count mismatch"));
    }
    let mut inputs = Vector::with_capacity(relocation_arenas.len())
        .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
    let mut archive_group = Vector::with_capacity(relocation_arenas.len())
        .map_err(|_| anyhow!("could not allocate decoded link origin list"))?;
    let mut archive_member = Vector::with_capacity(relocation_arenas.len())
        .map_err(|_| anyhow!("could not allocate decoded link member list"))?;
    let mut source_object = Vector::with_capacity(relocation_arenas.len())
        .map_err(|_| anyhow!("could not allocate decoded source-object list"))?;
    let mut comdat_selection = Vector::with_capacity(relocation_arenas.len())
        .map_err(|_| anyhow!("could not allocate decoded COMDAT list"))?;
    let mut remaining_arenas = relocation_arenas;
    let mut remaining_definitions = definition_arenas;
    for (object_index, object) in objects.iter().enumerate() {
        let coff_short_import = match format {
            ObjectFormat::Coff => x86_64_coff_short_import(object).map_err(|error| {
                anyhow!("COFF object {} short import: {}", object_index, error)
            })?,
            ObjectFormat::Elf64 => None,
        };
        let coff_comdat_sections = match format {
            ObjectFormat::Coff if coff_short_import.is_none() => Some(
                inventory_x86_64_coff_comdat_sections(object).map_err(|error| {
                    anyhow!("COFF object {} COMDAT inventory: {}", object_index, error)
                })?,
            ),
            ObjectFormat::Coff | ObjectFormat::Elf64 => None,
        };
        let text_fragment_count = match format {
            ObjectFormat::Coff if coff_short_import.is_some() => 1,
            ObjectFormat::Coff => x86_64_coff_text_fragment_count(object).map_err(|error| {
                anyhow!(
                    "COFF object {} text fragment count: {}",
                    object_index,
                    error
                )
            })?,
            ObjectFormat::Elf64 => 1,
        };
        let readonly_fragment_count = match format {
            ObjectFormat::Coff if coff_short_import.is_some() => 0,
            ObjectFormat::Coff => x86_64_coff_section_identity_readonly_fragment_count(
                object,
                coff_comdat_sections
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing COFF COMDAT inventory"))?,
            )
            .map_err(|error| {
                anyhow!(
                    "COFF object {} read-only fragment count: {}",
                    object_index,
                    error
                )
            })?,
            ObjectFormat::Elf64 => 0,
        };
        let fragment_count = text_fragment_count
            .checked_add(readonly_fragment_count)
            .ok_or_else(|| anyhow!("expanded link fragment count overflow"))?;
        if inputs
            .len()
            .checked_add(fragment_count)
            .unwrap_or(usize::MAX)
            > MAX_LINK_FRAGMENTS
        {
            return Err(anyhow!("expanded link fragment capacity exceeded"));
        }
        for fragment_index in 0..fragment_count {
            let (arena, rest) = remaining_arenas
                .split_first_mut()
                .ok_or_else(|| anyhow!("link relocation arena count mismatch"))?;
            let (definitions, definition_rest) = remaining_definitions
                .split_first_mut()
                .ok_or_else(|| anyhow!("link definition arena count mismatch"))?;
            let (input, selection_policy) = match format {
                ObjectFormat::Coff if coff_short_import.is_some() => (
                    decode_x86_64_coff_short_import(object, arena)
                        .map_err(|error| {
                            anyhow!("COFF object {} short import decode: {}", object_index, error)
                        })?
                        .ok_or_else(|| anyhow!("COFF short import changed after inventory"))?,
                    CoffTextComdatSelection::None,
                ),
                ObjectFormat::Coff if fragment_index < text_fragment_count => {
                    let inventory = coff_comdat_sections
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing COFF COMDAT inventory"))?;
                    (
                        decode_x86_64_coff_text_fragment_with_section_identities_from_inventory(
                            object,
                            fragment_index,
                            inventory,
                            u16::try_from(object_index + 1)
                                .map_err(|_| anyhow!("COFF source-object identity overflow"))?,
                            arena,
                            definitions,
                        )
                        .map_err(|error| {
                            anyhow!(
                                "COFF object {} archive group {} member {} text fragment {}: {}",
                                object_index,
                                object_archive_group[object_index],
                                object_archive_member[object_index],
                                fragment_index,
                                error
                            )
                        })?,
                        x86_64_coff_text_fragment_comdat_selection_from_inventory(
                            object,
                            fragment_index,
                            inventory,
                        )
                        .map_err(|error| {
                            anyhow!(
                                "COFF object {} archive group {} member {} text fragment {} selection: {}",
                                object_index,
                                object_archive_group[object_index],
                                object_archive_member[object_index],
                                fragment_index,
                                error
                            )
                        })?,
                    )
                }
                ObjectFormat::Coff => {
                    let decoded = decode_x86_64_coff_section_identity_readonly_fragment(
                        object,
                        fragment_index - text_fragment_count,
                        coff_comdat_sections
                            .as_ref()
                            .ok_or_else(|| anyhow!("missing COFF COMDAT inventory"))?,
                        u16::try_from(object_index + 1)
                            .map_err(|_| anyhow!("COFF source-object identity overflow"))?,
                        definitions,
                    )
                    .map_err(|error| {
                        let readonly_index = fragment_index - text_fragment_count;
                        anyhow!(
                            "COFF object {} archive group {} member {} read-only fragment {}: {}",
                            object_index,
                            object_archive_group[object_index],
                            object_archive_member[object_index],
                            readonly_index,
                            error
                        )
                    })?;
                    (decoded.input, decoded.selection)
                }
                ObjectFormat::Elf64 => (
                    decode_x86_64_elf_with_definitions(object, arena, definitions)
                        .map_err(mrml_error::message)?,
                    CoffTextComdatSelection::None,
                ),
            };
            inputs
                .try_push(input)
                .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
            archive_group
                .try_push(object_archive_group[object_index])
                .map_err(|_| anyhow!("could not allocate decoded link origin list"))?;
            archive_member
                .try_push(object_archive_member[object_index])
                .map_err(|_| anyhow!("could not allocate decoded link member list"))?;
            source_object
                .try_push(object_index)
                .map_err(|_| anyhow!("could not allocate decoded source-object list"))?;
            comdat_selection
                .try_push(selection_policy)
                .map_err(|_| anyhow!("could not allocate decoded COMDAT list"))?;
            remaining_arenas = rest;
            remaining_definitions = definition_rest;
        }
    }
    Ok(DecodedLinkInputs {
        inputs,
        archive_group,
        archive_member,
        source_object,
        comdat_selection,
    })
}

fn definition_arenas<'a>(
    count: usize,
) -> Result<Vector<[LinkDefinition<'a>; MAX_LINK_DEFINITIONS]>> {
    let mut arenas = Vector::with_capacity(count)
        .map_err(|_| anyhow!("could not allocate link definition arenas"))?;
    for _ in 0..count {
        arenas
            .try_push(
                [LinkDefinition {
                    symbol: "unused",
                    target: LinkDefinitionTarget::Text(0),
                }; MAX_LINK_DEFINITIONS],
            )
            .map_err(|_| anyhow!("could not allocate link definition arenas"))?;
    }
    Ok(arenas)
}

fn relocation_arenas<'a>(
    count: usize,
) -> Result<Vector<[LinkRelocation<'a>; MAX_LINK_RELOCATIONS]>> {
    let mut arenas = Vector::with_capacity(count)
        .map_err(|_| anyhow!("could not allocate link relocation arenas"))?;
    for _ in 0..count {
        arenas
            .try_push(
                [LinkRelocation {
                    offset: 0,
                    target: LinkRelocationTarget::Symbol("unused"),
                    addend: 0,
                }; MAX_LINK_RELOCATIONS],
            )
            .map_err(|_| anyhow!("could not allocate link relocation arenas"))?;
    }
    Ok(arenas)
}

fn expanded_fragment_count(objects: &[&[u8]], format: ObjectFormat) -> Result<usize> {
    let mut count = 0usize;
    for (object_index, object) in objects.iter().enumerate() {
        let object_fragments = match format {
            ObjectFormat::Coff => {
                if x86_64_coff_short_import(object)
                    .map_err(|error| anyhow!("COFF object {} short import: {}", object_index, error))?
                    .is_some()
                {
                    1
                } else {
                let inventory = inventory_x86_64_coff_comdat_sections(object).map_err(|error| {
                    anyhow!("COFF object {} COMDAT inventory: {}", object_index, error)
                })?;
                x86_64_coff_text_fragment_count(object)
                    .map_err(|error| {
                        anyhow!(
                            "COFF object {} text fragment count: {}",
                            object_index,
                            error
                        )
                    })?
                    .checked_add(
                        x86_64_coff_section_identity_readonly_fragment_count(object, &inventory)
                            .map_err(|error| {
                                anyhow!(
                                    "COFF object {} read-only fragment count: {}",
                                    object_index,
                                    error
                                )
                            })?,
                    )
                    .ok_or_else(|| anyhow!("expanded link fragment count overflow"))?
                }
            }
            ObjectFormat::Elf64 => 1,
        };
        count = count
            .checked_add(object_fragments)
            .ok_or_else(|| anyhow!("expanded link fragment count overflow"))?;
        if count > MAX_LINK_FRAGMENTS {
            return Err(anyhow!("expanded link fragment capacity exceeded"));
        }
    }
    Ok(count)
}

fn selected_link_inputs<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    source_object: &[usize],
    comdat_selection: &[CoffTextComdatSelection],
    entry: &str,
) -> Result<SelectedLinkInputs<'data, 'relocations, 'definitions>> {
    if inputs.len() != source_object.len() || inputs.len() != comdat_selection.len() {
        return Err(anyhow!("decoded source-object count mismatch"));
    }
    let selection =
        select_ordered_static_link_members(inputs, archive_group, archive_member, entry)
            .map_err(|_| anyhow!("could not select static link members"))?;
    let mut selected: Vector<LinkInput<'data, 'relocations, 'definitions>> =
        Vector::with_capacity(selection.indices().len())
            .map_err(|_| anyhow!("could not allocate selected link input list"))?;
    let mut selected_group = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link origin list"))?;
    let mut selected_member = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link member list"))?;
    let mut selected_comdat = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected COMDAT list"))?;
    let mut selected_source_object = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected source-object list"))?;
    for index in selection.indices() {
        let current_is_internal = matches!(
            inputs[*index].symbol_target,
            LinkDefinitionTarget::CoffTextSection { .. }
                | LinkDefinitionTarget::CoffSection { .. }
        );
        if let Some(earlier) = (!current_is_internal)
            .then(|| {
                selected.iter().position(|earlier| {
                    !matches!(
                        earlier.symbol_target,
                        LinkDefinitionTarget::CoffTextSection { .. }
                            | LinkDefinitionTarget::CoffSection { .. }
                    ) && earlier.symbol == inputs[*index].symbol
                })
            })
            .flatten()
        {
            let earlier_selection = selected_comdat[earlier];
            let current_selection = comdat_selection[*index];
            let mut effective_selection = earlier_selection;
            let mut replace = false;
            let (earlier_payload, current_payload) = match (
                selected[earlier].symbol_target,
                inputs[*index].symbol_target,
            ) {
                (LinkDefinitionTarget::Text(0), LinkDefinitionTarget::Text(0)) => {
                    (selected[earlier].text, inputs[*index].text)
                }
                (LinkDefinitionTarget::ReadonlyData(0), LinkDefinitionTarget::ReadonlyData(0)) => (
                    selected[earlier].readonly_data,
                    inputs[*index].readonly_data,
                ),
                _ => return Err(anyhow!("incompatible duplicate COFF definition kinds")),
            };
            let compatible = match (earlier_selection, current_selection) {
                (CoffTextComdatSelection::Any, CoffTextComdatSelection::Any) => true,
                (CoffTextComdatSelection::SameSize, CoffTextComdatSelection::SameSize)
                | (CoffTextComdatSelection::Any, CoffTextComdatSelection::SameSize)
                | (CoffTextComdatSelection::SameSize, CoffTextComdatSelection::Any) => {
                    effective_selection = CoffTextComdatSelection::SameSize;
                    earlier_payload.len() == current_payload.len()
                }
                (CoffTextComdatSelection::ExactMatch, CoffTextComdatSelection::ExactMatch) => {
                    earlier_payload == current_payload
                }
                (CoffTextComdatSelection::Largest, CoffTextComdatSelection::Largest)
                | (CoffTextComdatSelection::Any, CoffTextComdatSelection::Largest)
                | (CoffTextComdatSelection::Largest, CoffTextComdatSelection::Any) => {
                    effective_selection = CoffTextComdatSelection::Largest;
                    replace = current_payload.len() > earlier_payload.len();
                    true
                }
                _ => false,
            };
            if compatible {
                if replace {
                    selected[earlier] = inputs[*index];
                    selected_group[earlier] = archive_group[*index];
                    selected_member[earlier] = archive_member[*index];
                    selected_source_object[earlier] = source_object[*index];
                }
                selected_comdat[earlier] = effective_selection;
                continue;
            }
            return Err(anyhow!(
                "incompatible duplicate COFF definition {}: source object {} uses {:?}, source object {} uses {:?}",
                inputs[*index].symbol,
                selected_source_object[earlier],
                earlier_selection,
                source_object[*index],
                current_selection
            ));
        }
        selected
            .try_push(inputs[*index])
            .map_err(|_| anyhow!("could not allocate selected link input list"))?;
        selected_group
            .try_push(archive_group[*index])
            .map_err(|_| anyhow!("could not allocate selected link origin list"))?;
        selected_member
            .try_push(archive_member[*index])
            .map_err(|_| anyhow!("could not allocate selected link member list"))?;
        selected_comdat
            .try_push(comdat_selection[*index])
            .map_err(|_| anyhow!("could not allocate selected COMDAT list"))?;
        selected_source_object
            .try_push(source_object[*index])
            .map_err(|_| anyhow!("could not allocate selected source-object list"))?;
    }
    Ok(SelectedLinkInputs {
        inputs: selected,
        archive_group: selected_group,
        archive_member: selected_member,
        source_object: selected_source_object,
    })
}

fn selected_runtime_functions<'data>(
    objects: &[&'data [u8]],
    archive_group: &[u16],
    archive_member: &[u16],
    selected: &SelectedLinkInputs<'_, '_, '_>,
    arena: &mut [PeRuntimeFunction<'data>; MAX_PE_RUNTIME_FUNCTIONS],
) -> Result<Vector<PeRuntimeFunction<'data>>> {
    let mut runtime_functions = Vector::with_capacity(MAX_PE_RUNTIME_FUNCTIONS)
        .map_err(|_| anyhow!("could not allocate selected runtime-function list"))?;
    for object_index in 0..objects.len() {
        let selected_object = selected
            .source_object
            .iter()
            .any(|source| *source == object_index);
        if selected_object {
            for function in decode_x86_64_coff_runtime_functions_with_section_identities(
                objects[object_index],
                u16::try_from(object_index + 1)
                    .map_err(|_| anyhow!("COFF source-object identity overflow"))?,
                arena,
            )
                .map_err(|error| {
                    anyhow!(
                        "COFF object {} archive group {} member {} runtime-function decode: {}",
                        object_index,
                        archive_group[object_index],
                        archive_member[object_index],
                        error
                    )
                })?
            {
                let retained = selected
                    .inputs
                    .iter()
                    .zip(selected.source_object.iter())
                    .any(|(input, source)| {
                        if *source != object_index {
                            return false;
                        }
                        match function.begin_identity {
                            Some(identity) => matches!(
                                input.symbol_target,
                                LinkDefinitionTarget::CoffTextSection {
                                    identity: candidate,
                                    ..
                                } if candidate == identity
                            ) || input.additional_definitions.iter().any(|definition| {
                                matches!(
                                    definition.target,
                                    LinkDefinitionTarget::CoffTextSection {
                                        identity: candidate,
                                        ..
                                    } if candidate == identity
                                )
                            }),
                            None => input.symbol == function.begin_symbol
                                || input.additional_definitions.iter().any(|definition| {
                                    definition.symbol == function.begin_symbol
                                }),
                        }
                    });
                if !retained {
                    continue;
                }
                if runtime_functions.len() == MAX_PE_RUNTIME_FUNCTIONS {
                    return Err(anyhow!(
                        "selected PE runtime-function count exceeds {}",
                        MAX_PE_RUNTIME_FUNCTIONS
                    ));
                }
                runtime_functions
                    .try_push(*function)
                    .map_err(|_| anyhow!("could not allocate selected runtime-function list"))?;
            }
        }
    }
    Ok(runtime_functions)
}

fn writable_relocation_arenas<'a>(
    count: usize,
) -> Result<Vector<[PeWritableRelocation<'a>; MAX_LINK_RELOCATIONS]>> {
    let mut arenas = Vector::with_capacity(count)
        .map_err(|_| anyhow!("could not allocate writable relocation arenas"))?;
    for _ in 0..count {
        arenas
            .try_push(
                [PeWritableRelocation {
                    offset: 0,
                    target: PeWritableRelocationTarget::Readonly {
                        owner: "unused",
                        offset: 0,
                    },
                }; MAX_LINK_RELOCATIONS],
            )
            .map_err(|_| anyhow!("could not allocate writable relocation arenas"))?;
    }
    Ok(arenas)
}

fn writable_fragment_count(objects: &[&[u8]]) -> Result<usize> {
    let mut count = 0usize;
    for object in objects {
        count = count
            .checked_add(
                x86_64_coff_writable_section_count(object)
                    .map_err(|_| anyhow!("could not count writable COFF fragments"))?,
            )
            .ok_or_else(|| anyhow!("writable fragment count overflow"))?;
    }
    if count > MAX_LINK_INPUTS {
        return Err(anyhow!("too many writable COFF fragments: {count}"));
    }
    Ok(count)
}

fn selected_writable_data<'data, 'relocations>(
    objects: &[&'data [u8]],
    archive_group: &[u16],
    archive_member: &[u16],
    selected: &SelectedLinkInputs<'data, '_, '_>,
    arenas: &'relocations mut [[PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS]],
) -> Result<Vector<PeWritableData<'data, 'relocations>>> {
    let mut output = Vector::with_capacity(arenas.len())
        .map_err(|_| anyhow!("could not allocate selected writable data list"))?;
    let mut remaining = arenas;
    for object_index in 0..objects.len() {
        let group = archive_group[object_index];
        let member = archive_member[object_index];
        let owner = selected
            .inputs
            .iter()
            .zip(
                selected
                    .archive_group
                    .iter()
                    .zip(selected.archive_member.iter()),
            )
            .find(|(_, (selected_group, selected_member))| {
                **selected_group == group && **selected_member == member
            })
            .map(|(input, _)| input.symbol);
        if let Some(owner) = owner {
            let fragment_count = x86_64_coff_writable_section_count(objects[object_index])
                .map_err(|error| {
                    anyhow!(
                        "COFF object {} writable fragment count: {}",
                        object_index,
                        error
                    )
                })?;
            for fragment_index in 0..fragment_count {
                let (arena, rest) = remaining
                    .split_first_mut()
                    .ok_or_else(|| anyhow!("writable relocation arena count mismatch"))?;
                let data = decode_x86_64_coff_writable_data_fragment_with_section_identities(
                    objects[object_index],
                    fragment_index,
                    owner,
                    u16::try_from(object_index + 1)
                        .map_err(|_| anyhow!("COFF source-object identity overflow"))?,
                    arena,
                )
                .map_err(|error| {
                    anyhow!(
                        "COFF object {} writable fragment {}: {}",
                        object_index,
                        fragment_index,
                        error
                    )
                })?;
                output
                    .try_push(data)
                    .map_err(|_| anyhow!("could not allocate selected writable data list"))?;
                remaining = rest;
            }
        }
    }
    Ok(output)
}

fn selected_readonly_absolute_relocations<'data>(
    objects: &[&'data [u8]],
    _archive_group: &[u16],
    _archive_member: &[u16],
    selected: &SelectedLinkInputs<'data, '_, '_>,
) -> Result<Vector<PeReadonlyAbsoluteRelocation<'data>>> {
    let mut output = Vector::with_capacity(MAX_PE_READONLY_RELOCATIONS)
        .map_err(|_| anyhow!("could not allocate selected COFF refptr list"))?;
    for object_index in 0..objects.len() {
        let selected_object = selected
            .source_object
            .iter()
            .any(|source| *source == object_index);
        if selected_object {
            let object = objects[object_index];
            let inventory = inventory_x86_64_coff_comdat_sections(object).map_err(|error| {
                anyhow!(
                    "COFF object {} selected-section inventory: {}",
                    object_index,
                    error
                )
            })?;
            let decoded =
                decode_x86_64_coff_readonly_absolute_relocations_with_section_identities_from_inventory(
                    object,
                    &inventory,
                    u16::try_from(object_index + 1)
                        .map_err(|_| anyhow!("COFF source-object identity overflow"))?,
                )
                    .map_err(|error| {
                        anyhow!(
                            "COFF object {} selected read-only relocations: {}",
                            object_index,
                            error
                        )
                    })?;
            for relocation in decoded.relocations() {
                let retained = selected.inputs.iter().zip(selected.source_object.iter()).any(
                    |(input, source)| {
                        if *source != object_index {
                            return false;
                        }
                        match relocation.readonly_identity {
                            Some(identity) => matches!(
                                input.symbol_target,
                                LinkDefinitionTarget::CoffSection {
                                    identity: candidate,
                                    ..
                                } if candidate == identity
                            ),
                            None => input.symbol == relocation.readonly_owner,
                        }
                    },
                );
                if retained {
                    if output.len() == MAX_PE_READONLY_RELOCATIONS {
                        return Err(anyhow!("too many selected COFF readonly relocations"));
                    }
                    output
                        .try_push(*relocation)
                        .map_err(|_| anyhow!("could not allocate selected COFF readonly list"))?;
                }
            }
        }
    }
    Ok(output)
}

fn contextualize_pe_writable_relocations<'data, 'definitions, 'relocations>(
    inputs: &[LinkInput<'data, '_, 'definitions>],
    writable_data: &[PeWritableData<'data, '_>],
    arenas: &'relocations mut [[LinkRelocation<'data>; MAX_LINK_RELOCATIONS]],
) -> Result<Vector<LinkInput<'data, 'relocations, 'definitions>>> {
    if inputs.len() != arenas.len() {
        return Err(anyhow!("contextual relocation arena count mismatch"));
    }
    let link_target_defined = |symbol: &str| {
        inputs.iter().any(|input| {
            (!matches!(
                input.symbol_target,
                LinkDefinitionTarget::CoffTextSection { .. }
                    | LinkDefinitionTarget::CoffSection { .. }
            ) && input.symbol == symbol)
                || input.additional_definitions.iter().any(|definition| {
                    !matches!(
                        definition.target,
                        LinkDefinitionTarget::CoffTextSection { .. }
                            | LinkDefinitionTarget::CoffSection { .. }
                    ) && definition.symbol == symbol
                })
        })
    };
    let writable_target_defined = |symbol: &str| {
        writable_data.iter().any(|data| data.symbol == symbol)
    };
    let mut contextual = Vector::with_capacity(inputs.len())
        .map_err(|_| anyhow!("could not allocate contextual PE link inputs"))?;
    let mut remaining = arenas;
    for input in inputs {
        let (arena, rest) = remaining
            .split_first_mut()
            .ok_or_else(|| anyhow!("contextual relocation arena count mismatch"))?;
        if input.relocations.len() > arena.len() {
            return Err(anyhow!("contextual relocation capacity exceeded"));
        }
        for (index, relocation) in input.relocations.iter().copied().enumerate() {
            arena[index] = match relocation.target {
                LinkRelocationTarget::Symbol(symbol)
                    if !link_target_defined(symbol) && writable_target_defined(symbol) =>
                {
                    LinkRelocation {
                        target: LinkRelocationTarget::PeWritableSymbol(symbol),
                        ..relocation
                    }
                }
                _ => relocation,
            };
        }
        contextual
            .try_push(LinkInput {
                symbol: input.symbol,
                symbol_target: input.symbol_target,
                additional_definitions: input.additional_definitions,
                text: input.text,
                readonly_data: input.readonly_data,
                relocations: &arena[..input.relocations.len()],
            })
            .map_err(|_| anyhow!("could not allocate contextual PE link inputs"))?;
        remaining = rest;
    }
    Ok(contextual)
}

fn write_linked_pe(
    objects: &[&[u8]],
    archive_group: &[u16],
    archive_member: &[u16],
    entry: &str,
    output: &str,
) -> Result<()> {
    let fragment_count = expanded_fragment_count(objects, ObjectFormat::Coff)?;
    let mut arenas = relocation_arenas(fragment_count)?;
    let mut definitions = definition_arenas(fragment_count)?;
    let decoded = decode_link_inputs(
        objects,
        archive_group,
        archive_member,
        ObjectFormat::Coff,
        &mut arenas,
        &mut definitions,
    )?;
    let selected = selected_link_inputs(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        &decoded.source_object,
        &decoded.comdat_selection,
        entry,
    )?;
    let mut runtime_arena = [PeRuntimeFunction {
        begin_symbol: "unused",
        begin_identity: None,
        begin_offset: 0,
        end_symbol: "unused",
        end_identity: None,
        end_offset: 0,
        unwind_info: &[],
    }; MAX_PE_RUNTIME_FUNCTIONS];
    let runtime_functions = selected_runtime_functions(
        objects,
        archive_group,
        archive_member,
        &selected,
        &mut runtime_arena,
    )?;
    let mut writable_arenas = writable_relocation_arenas(writable_fragment_count(objects)?)?;
    let writable_data = selected_writable_data(
        objects,
        archive_group,
        archive_member,
        &selected,
        &mut writable_arenas,
    )?;
    let readonly_absolute_relocations =
        selected_readonly_absolute_relocations(objects, archive_group, archive_member, &selected)?;
    let mut contextual_arenas = relocation_arenas(selected.inputs.len())?;
    let contextual_inputs = contextualize_pe_writable_relocations(
        &selected.inputs,
        &writable_data,
        &mut contextual_arenas,
    )?;
    let payload = selected_payload_bound(&contextual_inputs, &runtime_functions, &writable_data)?;
    if payload <= 16 * 1024 {
        return write_pe_image::<{ 32 * 1024 }, { 16 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        );
    }
    if payload <= 256 * 1024 {
        return write_pe_image::<{ 512 * 1024 }, { 256 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        );
    }
    if payload <= 512 * 1024 {
        return write_pe_image::<{ 1024 * 1024 }, { 512 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        );
    }
    if payload <= 1024 * 1024 {
        return write_pe_image::<{ 768 * 1024 }, { 768 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        );
    }
    write_pe_image::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(
        &contextual_inputs,
        &runtime_functions,
        &writable_data,
        &readonly_absolute_relocations,
        entry,
        output,
    )
}

fn write_pe_image<const MAX_IMAGE: usize, const MAX_LINKED: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
    readonly_absolute_relocations: &[PeReadonlyAbsoluteRelocation<'_>],
    entry: &str,
    output: &str,
) -> Result<()> {
    let link_target_defined = |symbol: &str| {
        inputs.iter().any(|input| {
            (!matches!(
                input.symbol_target,
                LinkDefinitionTarget::CoffTextSection { .. }
                    | LinkDefinitionTarget::CoffSection { .. }
            )
                && input.symbol == symbol)
                || input.additional_definitions.iter().any(|definition| {
                    !matches!(
                        definition.target,
                        LinkDefinitionTarget::CoffTextSection { .. }
                            | LinkDefinitionTarget::CoffSection { .. }
                    )
                        && definition.symbol == symbol
                })
        })
    };
    let writable_target_defined = |symbol: &str| {
        writable_data.iter().any(|data| data.symbol == symbol)
    };
    let named_target_defined = |symbol: &str| {
        link_target_defined(symbol) || writable_target_defined(symbol)
    };
    let section_identity_defined = |identity: CoffSectionIdentity| {
        inputs.iter().any(|input| {
            matches!(input.symbol_target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                || input.additional_definitions.iter().any(|definition| {
                    matches!(definition.target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                })
        })
    };
    for relocation in readonly_absolute_relocations {
        if let Some(identity) = relocation.readonly_identity
            && !section_identity_defined(identity)
        {
            return Err(anyhow!(
                "selected read-only relocation owner section is undefined: object {}, section {}",
                identity.object(),
                identity.section()
            ));
        }
        if relocation.readonly_identity.is_none()
            && !named_target_defined(relocation.readonly_owner)
        {
            return Err(anyhow!(
                "selected read-only relocation owner is undefined: {}",
                relocation.readonly_owner
            ));
        }
        if relocation.target_identity.is_none()
            && !named_target_defined(relocation.target_symbol)
        {
            return Err(anyhow!(
                "selected read-only relocation target is undefined: {}",
                relocation.target_symbol
            ));
        }
        if let Some(identity) = relocation.target_identity
            && !section_identity_defined(identity)
        {
            return Err(anyhow!(
                "selected read-only relocation target section is undefined: object {}, section {}",
                identity.object(),
                identity.section()
            ));
        }
    }
    for input in inputs {
        for relocation in input.relocations {
            if let LinkRelocationTarget::Symbol(symbol)
            | LinkRelocationTarget::GotPcRelativeSymbol(symbol)
            | LinkRelocationTarget::RequiredSymbol(symbol)
            | LinkRelocationTarget::LocalSymbol(symbol) = relocation.target
                && !link_target_defined(symbol)
            {
                return Err(anyhow!(
                    "selected code relocation target is undefined: {}",
                    symbol
                ));
            }
            if let LinkRelocationTarget::PeWritableSymbol(symbol) = relocation.target
                && !writable_target_defined(symbol)
            {
                return Err(anyhow!(
                    "selected code relocation writable target is undefined: {}",
                    symbol
                ));
            }
            if let LinkRelocationTarget::PeImportAddress { library, symbol } = relocation.target {
                return Err(anyhow!(
                    "selected PE import table emission is unsupported: {}!{}",
                    library,
                    symbol
                ));
            }
            if let LinkRelocationTarget::PeTlsSection { identity, .. } = relocation.target {
                return Err(anyhow!(
                    "selected PE TLS target is unsupported: object {}, section {}",
                    identity.object(),
                    identity.section()
                ));
            }
            if let LinkRelocationTarget::CoffSection { identity, .. } = relocation.target
                && !section_identity_defined(identity)
            {
                return Err(anyhow!(
                    "selected code relocation target section is undefined: object {}, section {}",
                    identity.object(),
                    identity.section()
                ));
            }
        }
    }
    for function in runtime_functions {
        for (identity, symbol) in [
            (function.begin_identity, function.begin_symbol),
            (function.end_identity, function.end_symbol),
        ] {
            match identity {
                Some(identity) if !section_identity_defined(identity) => {
                    return Err(anyhow!(
                        "selected runtime-function target section is undefined: object {}, section {}",
                        identity.object(),
                        identity.section()
                    ));
                }
                None if !named_target_defined(symbol) => {
                    return Err(anyhow!(
                        "selected runtime-function target is undefined: {}",
                        symbol
                    ));
                }
                _ => {}
            }
        }
    }
    for data in writable_data {
        for relocation in data.relocations {
            match relocation.target {
                PeWritableRelocationTarget::Readonly { owner, .. }
                    if !named_target_defined(owner) =>
                {
                    return Err(anyhow!(
                        "selected writable relocation read-only owner is undefined: {}",
                        owner
                    ));
                }
                PeWritableRelocationTarget::WritableSymbol(symbol)
                    if !named_target_defined(symbol) =>
                {
                    return Err(anyhow!(
                        "selected writable relocation target is undefined: {}",
                        symbol
                    ));
                }
                PeWritableRelocationTarget::CoffSection { identity, .. }
                    if !section_identity_defined(identity) =>
                {
                    return Err(anyhow!(
                        "selected writable relocation target section is undefined: object {}, section {}",
                        identity.object(),
                        identity.section()
                    ));
                }
                _ => {}
            }
        }
    }
    let executable =
        link_x86_64_pe_with_data_unwind_and_readonly_relocations::<MAX_IMAGE, MAX_LINKED>(
            inputs,
            entry,
            runtime_functions,
            writable_data,
            readonly_absolute_relocations,
        )
        .map_err(|error| {
            anyhow!(
                "could not serialize linked PE image: {} (runtime functions {}, read-only relocations {})",
                error,
                runtime_functions.len(),
                readonly_absolute_relocations.len()
            )
        })?;
    mrml_runtime::write_file(output, executable.bytes())?;
    println!(
        "linked {} to {} deterministic PE bytes",
        entry,
        executable.bytes().len()
    );
    Ok(())
}

fn write_linked_elf(
    objects: &[&[u8]],
    _archive_group: &[u16],
    _archive_member: &[u16],
    entry: &str,
    output: &str,
) -> Result<()> {
    let link_selection = select_x86_64_elf_link_sections_detailed(objects, entry)
        .map_err(|error| anyhow!("could not select reachable ELF sections: {}", error))?;
    let mut sections: Vector<ElfSelectedSections<'_>> = Vector::with_capacity(objects.len())
        .map_err(|_| anyhow!("could not allocate selected ELF section views"))?;
    let mut definitions: Vector<ElfSelectedDefinitions<'_>> = Vector::with_capacity(objects.len())
        .map_err(|_| anyhow!("could not allocate selected ELF definition views"))?;
    let mut relocations: Vector<ElfSelectedRelocations<'_>> = Vector::with_capacity(objects.len())
        .map_err(|_| anyhow!("could not allocate selected ELF relocation views"))?;
    for (object, selection) in objects.iter().zip(link_selection.selections()) {
        sections
            .try_push(
                decode_x86_64_elf_selected_sections(object, selection).map_err(|error| {
                    anyhow!("could not decode reachable ELF sections: {}", error)
                })?,
            )
            .map_err(|_| anyhow!("could not allocate selected ELF section views"))?;
        definitions
            .try_push(
                decode_x86_64_elf_selected_definitions_from_sections(
                    object,
                    selection,
                    sections
                        .last()
                        .ok_or_else(|| anyhow!("selected ELF section view is missing"))?,
                )
                .map_err(|error| {
                    anyhow!("could not decode reachable ELF definitions: {}", error)
                })?,
            )
            .map_err(|_| anyhow!("could not allocate selected ELF definition views"))?;
        relocations
            .try_push(
                decode_x86_64_elf_selected_relocations_from_sections(
                    object,
                    selection,
                    sections
                        .last()
                        .ok_or_else(|| anyhow!("selected ELF section view is missing"))?,
                )
                .map_err(|error| {
                    anyhow!("could not decode reachable ELF relocations: {}", error)
                })?,
            )
            .map_err(|_| anyhow!("could not allocate selected ELF relocation views"))?;
    }
    let mut selected = Vector::with_capacity(objects.len())
        .map_err(|_| anyhow!("could not allocate selected ELF object views"))?;
    for index in 0..objects.len() {
        selected
            .try_push(ElfSelectedObject {
                sections: &sections[index],
                definitions: &definitions[index],
                relocations: &relocations[index],
            })
            .map_err(|_| anyhow!("could not allocate selected ELF object views"))?;
    }
    let mut payload = 4096usize;
    for view in &sections {
        for section in view.sections() {
            payload = payload
                .checked_add(section.size)
                .and_then(|bytes| bytes.checked_add(4096))
                .ok_or_else(|| anyhow!("selected ELF payload size overflow"))?;
        }
    }
    if payload <= 16 * 1024 {
        return write_selected_elf_image::<{ 32 * 1024 }, { 16 * 1024 }>(&selected, entry, output);
    }
    if payload <= 256 * 1024 {
        return write_selected_elf_image::<{ 512 * 1024 }, { 256 * 1024 }>(
            &selected, entry, output,
        );
    }
    write_selected_elf_image::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&selected, entry, output)
}

fn write_selected_elf_image<const MAX_IMAGE: usize, const MAX_PAYLOAD: usize>(
    inputs: &[ElfSelectedObject<'_, '_>],
    entry: &str,
    output: &str,
) -> Result<()> {
    let executable = link_x86_64_elf_selected_executable::<MAX_IMAGE, MAX_PAYLOAD>(inputs, entry)
        .map_err(mrml_error::message)?;
    mrml_runtime::write_file(output, executable.bytes())?;
    println!(
        "linked {} to {} deterministic selected-section ELF64 bytes",
        entry,
        executable.bytes().len()
    );
    Ok(())
}

fn selected_payload_bound(
    inputs: &[LinkInput<'_, '_, '_>],
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
) -> Result<usize> {
    let mut bytes = 4096usize;
    for input in inputs {
        bytes = bytes
            .checked_add(input.text.len())
            .and_then(|bytes| bytes.checked_add(input.readonly_data.len()))
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or_else(|| anyhow!("selected link payload size overflow"))?;
    }
    for function in runtime_functions {
        bytes = bytes
            .checked_add(function.unwind_info.len())
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or_else(|| anyhow!("selected unwind payload size overflow"))?;
    }
    for data in writable_data {
        bytes = bytes
            .checked_add(data.initialized.len())
            .and_then(|bytes| bytes.checked_add(data.zeroed_size))
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or_else(|| anyhow!("selected writable payload size overflow"))?;
    }
    Ok(bytes)
}

fn parse_emit_kind(value: &str) -> Result<EmitKind> {
    match value {
        "elf64" => Ok(EmitKind::Object(ObjectFormat::Elf64)),
        "coff" => Ok(EmitKind::Object(ObjectFormat::Coff)),
        "pe" => Ok(EmitKind::Pe),
        "elf-executable" => Ok(EmitKind::ElfExecutable),
        _ => Err(anyhow!(
            "emit kind must be elf64, coff, pe, or elf-executable"
        )),
    }
}

fn parse_codegen_options(value: &str) -> Result<CodegenOptions> {
    match value {
        "overflow-checks=yes" | "overflow-checks=on" => Ok(CodegenOptions::CHECKED),
        "overflow-checks=no" | "overflow-checks=off" => Ok(CodegenOptions::WRAPPING),
        _ => Err(anyhow!("overflow-checks must be yes or no")),
    }
}

mrml_runtime::mrml_entrypoint!(application_main);

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with_linker_stack(test: fn()) {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    }

    fn append_archive_member(archive: &mut Vector<u8>, name: &str, bytes: &[u8]) {
        let mut header = [b' '; 60];
        let name = name.as_bytes();
        header[..name.len()].copy_from_slice(name);
        let mut size = bytes.len();
        let mut digits = [0u8; 10];
        let mut count = 0usize;
        loop {
            digits[count] = b'0' + u8::try_from(size % 10).unwrap();
            count += 1;
            size /= 10;
            if size == 0 {
                break;
            }
        }
        for index in 0..count {
            header[48 + index] = digits[count - index - 1];
        }
        header[58..60].copy_from_slice(b"`\n");
        for byte in header.into_iter().chain(bytes.iter().copied()) {
            archive.try_push(byte).unwrap();
        }
        if bytes.len() % 2 != 0 {
            archive.try_push(b'\n').unwrap();
        }
    }

    #[test]
    fn parses_only_supported_object_formats() {
        assert_eq!(
            parse_emit_kind("elf64").unwrap(),
            EmitKind::Object(ObjectFormat::Elf64)
        );
        assert_eq!(
            parse_emit_kind("coff").unwrap(),
            EmitKind::Object(ObjectFormat::Coff)
        );
        assert_eq!(parse_emit_kind("pe").unwrap(), EmitKind::Pe);
        assert_eq!(
            parse_emit_kind("elf-executable").unwrap(),
            EmitKind::ElfExecutable
        );
        assert!(parse_emit_kind("exe").is_err());
    }

    #[test]
    fn parses_rustc_style_overflow_check_options() {
        assert_eq!(
            parse_codegen_options("overflow-checks=yes").unwrap(),
            CodegenOptions::CHECKED
        );
        assert_eq!(
            parse_codegen_options("overflow-checks=no").unwrap(),
            CodegenOptions::WRAPPING
        );
        assert!(parse_codegen_options("overflow-checks=maybe").is_err());
    }

    #[test]
    fn materializes_thin_members_as_valid_bounded_archive_members() {
        let mut archive = Vector::with_capacity(256).unwrap();
        archive.try_extend_from_slice(b"!<arch>\n").unwrap();
        append_materialized_archive_member(&mut archive, "objects/helper.o", b"object").unwrap();
        let decoded = decode_unix_archive(&archive).unwrap();
        assert_eq!(decoded.members().len(), 1);
        assert_eq!(decoded.members()[0].name, "objects/helper.o");
        assert_eq!(decoded.members()[0].bytes, b"object");
        assert!(!decoded.members()[0].external);
    }

    #[test]
    fn bounds_selected_payload_with_per_input_alignment_headroom() {
        let inputs = [
            LinkInput {
                symbol: "a",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0; 3],
                readonly_data: &[0; 5],
                relocations: &[],
            },
            LinkInput {
                symbol: "b",
                symbol_target: LinkDefinitionTarget::Text(0),
                additional_definitions: &[],
                text: &[0; 7],
                readonly_data: &[],
                relocations: &[],
            },
        ];
        assert_eq!(
            selected_payload_bound(&inputs, &[], &[]).unwrap(),
            4096 + 3 + 5 + 7 + 64
        );
    }

    #[test]
    fn contextualizes_only_unresolved_pe_writable_code_targets() {
        let relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("marker"),
            addend: -4,
        }];
        let input = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &relocation,
        };
        let writable = [PeWritableData {
            symbol: "marker",
            selection: mrml_rustc::PeWritableComdatSelection::NoDuplicates,
            initialized: &[0],
            zeroed_size: 0,
            relocations: &[],
        }];
        let mut arenas = relocation_arenas(1).unwrap();
        let contextual =
            contextualize_pe_writable_relocations(&[input], &writable, &mut arenas).unwrap();
        assert_eq!(
            contextual[0].relocations[0].target,
            LinkRelocationTarget::PeWritableSymbol("marker")
        );

        let definition = [LinkDefinition {
            symbol: "marker",
            target: LinkDefinitionTarget::Text(0),
        }];
        let defined = LinkInput {
            additional_definitions: &definition,
            ..input
        };
        let mut defined_arenas = relocation_arenas(1).unwrap();
        let defined_contextual = contextualize_pe_writable_relocations(
            &[defined],
            &writable,
            &mut defined_arenas,
        )
        .unwrap();
        assert_eq!(
            defined_contextual[0].relocations[0].target,
            LinkRelocationTarget::Symbol("marker")
        );
    }

    #[test]
    fn selects_leftmost_text_comdat_any_and_rejects_other_duplicates() {
        let first = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0x2a],
            readonly_data: &[],
            relocations: &[],
        };
        let second = LinkInput {
            text: &[0x63],
            ..first
        };
        let any = [CoffTextComdatSelection::Any; 2];
        let selected =
            selected_link_inputs(&[first, second], &[0, 0], &[0, 0], &[0, 1], &any, "entry")
                .unwrap();
        assert_eq!(selected.inputs.len(), 1);
        assert_eq!(selected.inputs[0].text, &[0x2a]);

        let strict = [
            CoffTextComdatSelection::Any,
            CoffTextComdatSelection::NoDuplicates,
        ];
        assert!(selected_link_inputs(
            &[first, second],
            &[0, 0],
            &[0, 0],
            &[0, 1],
            &strict,
            "entry",
        )
        .is_err());

        let same_size = [CoffTextComdatSelection::SameSize; 2];
        let selected = selected_link_inputs(
            &[first, second],
            &[0, 0],
            &[0, 0],
            &[0, 1],
            &same_size,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs[0].text, &[0x2a]);
        let longer = LinkInput {
            text: &[0x63, 0xc3],
            ..first
        };
        assert!(selected_link_inputs(
            &[first, longer],
            &[0, 0],
            &[0, 0],
            &[0, 1],
            &same_size,
            "entry",
        )
        .is_err());

        let exact = [CoffTextComdatSelection::ExactMatch; 2];
        assert!(
            selected_link_inputs(&[first, second], &[0, 0], &[0, 0], &[0, 1], &exact, "entry",)
                .is_err()
        );
        let same_section = LinkInput {
            readonly_data: &[0x99],
            ..first
        };
        let selected = selected_link_inputs(
            &[first, same_section],
            &[0, 0],
            &[0, 0],
            &[0, 1],
            &exact,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs.len(), 1);

        let largest = [CoffTextComdatSelection::Largest; 2];
        let selected = selected_link_inputs(
            &[first, longer],
            &[0, 0],
            &[0, 0],
            &[3, 7],
            &largest,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs[0].text, &[0x63, 0xc3]);
        assert_eq!(selected.source_object[0], 7);

        let any_largest = [
            CoffTextComdatSelection::Any,
            CoffTextComdatSelection::Largest,
        ];
        let selected = selected_link_inputs(
            &[first, longer],
            &[0, 0],
            &[0, 0],
            &[3, 7],
            &any_largest,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs[0].text, &[0x63, 0xc3]);
        assert_eq!(selected.source_object[0], 7);

        let largest_any = [
            CoffTextComdatSelection::Largest,
            CoffTextComdatSelection::Any,
        ];
        let selected = selected_link_inputs(
            &[longer, first],
            &[0, 0],
            &[0, 0],
            &[7, 3],
            &largest_any,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs[0].text, &[0x63, 0xc3]);
        assert_eq!(selected.source_object[0], 7);
    }

    #[test]
    fn selects_readonly_comdat_winners_by_payload_and_rebinds_origin() {
        let first = LinkInput {
            symbol: "literal",
            symbol_target: LinkDefinitionTarget::ReadonlyData(0),
            additional_definitions: &[],
            text: &[],
            readonly_data: b"A",
            relocations: &[],
        };
        let second = LinkInput {
            readonly_data: b"BB",
            ..first
        };
        let any = [CoffTextComdatSelection::Any; 2];
        let selected =
            selected_link_inputs(&[first, second], &[0, 0], &[0, 0], &[3, 7], &any, "literal")
                .unwrap();
        assert_eq!(selected.inputs.len(), 1);
        assert_eq!(selected.inputs[0].readonly_data, b"A");
        assert_eq!(selected.source_object[0], 3);

        let largest = [CoffTextComdatSelection::Largest; 2];
        let selected = selected_link_inputs(
            &[first, second],
            &[0, 0],
            &[0, 0],
            &[3, 7],
            &largest,
            "literal",
        )
        .unwrap();
        assert_eq!(selected.inputs[0].readonly_data, b"BB");
        assert_eq!(selected.source_object[0], 7);

        let same_size = [CoffTextComdatSelection::SameSize; 2];
        assert!(selected_link_inputs(
            &[first, second],
            &[0, 0],
            &[0, 0],
            &[3, 7],
            &same_size,
            "literal",
        )
        .is_err());
        let exact = [CoffTextComdatSelection::ExactMatch; 2];
        assert!(selected_link_inputs(
            &[first, second],
            &[0, 0],
            &[0, 0],
            &[3, 7],
            &exact,
            "literal",
        )
        .is_err());

        let entry_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("literal"),
            addend: -4,
        }];
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &entry_relocations,
        };
        let policies = [
            CoffTextComdatSelection::None,
            CoffTextComdatSelection::Any,
            CoffTextComdatSelection::Any,
        ];
        let selected = selected_link_inputs(
            &[entry, first, second],
            &[0, 0, 0],
            &[0, 0, 0],
            &[1, 3, 7],
            &policies,
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs.len(), 2);
        let linked = mrml_rustc::link_x86_64_static::<64>(&selected.inputs, "entry").unwrap();
        assert_eq!(
            i32::from_le_bytes(linked.bytes()[..4].try_into().unwrap()),
            12
        );
        assert_eq!(linked.bytes()[16], b'A');
    }

    #[test]
    fn preserves_archive_and_member_identity_before_fragment_expansion() {
        run_with_linker_stack(preserves_archive_and_member_identity_on_linker_stack);
    }

    fn preserves_archive_and_member_identity_on_linker_stack() {
        let first = compile_source_function_with_options::<4096, 4096, 8, 8, 8, 32>(
            "#[unsafe(no_mangle)] pub extern \"C\" fn first() -> i32 { 1 }",
            "first",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        let second = compile_source_function_with_options::<4096, 4096, 8, 8, 8, 32>(
            "#[unsafe(no_mangle)] pub extern \"C\" fn second() -> i32 { 2 }",
            "second",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        let explicit = compile_source_function_with_options::<4096, 4096, 8, 8, 8, 32>(
            "#[unsafe(no_mangle)] pub extern \"C\" fn entry() -> i32 { 3 }",
            "entry",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        let mut archive = Vector::with_capacity(16 * 1024).unwrap();
        for byte in b"!<arch>\n" {
            archive.try_push(*byte).unwrap();
        }
        append_archive_member(&mut archive, "first.o/", first.bytes());
        append_archive_member(&mut archive, "second.o/", second.bytes());
        let mut explicit_bytes = Vector::with_capacity(explicit.bytes().len()).unwrap();
        for byte in explicit.bytes() {
            explicit_bytes.try_push(*byte).unwrap();
        }
        let objects = [archive, explicit_bytes];
        let refs = link_object_refs(&objects, ObjectFormat::Elf64, "entry").unwrap();
        assert_eq!(&refs.archive_group[..], &[1, 1, 0]);
        assert_eq!(&refs.archive_member[..], &[1, 2, 0]);
    }

    #[test]
    fn indexed_archive_skips_hundreds_of_unreferenced_non_object_members() {
        run_with_linker_stack(indexed_archive_skips_hundreds_on_linker_stack);
    }

    fn indexed_archive_skips_hundreds_on_linker_stack() {
        let entry = compile_source_function_with_options::<4096, 4096, 8, 8, 8, 32>(
            "#[unsafe(no_mangle)] pub extern \"C\" fn entry() -> i32 { 42 }",
            "entry",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        let mut archive = Vector::with_capacity(64 * 1024).unwrap();
        for byte in b"!<arch>\n" {
            archive.try_push(*byte).unwrap();
        }
        let index = [0, 0, 0, 1, 0, 0, 0, 82, b'e', b'n', b't', b'r', b'y', 0];
        append_archive_member(&mut archive, "/", &index);
        append_archive_member(&mut archive, "entry.o/", entry.bytes());
        for _ in 0..300 {
            append_archive_member(&mut archive, "unused.o/", b"not an object");
        }

        let objects = [archive];
        let refs = link_object_refs(&objects, ObjectFormat::Elf64, "entry").unwrap();
        assert_eq!(refs.bytes.len(), 1);
        assert_eq!(&refs.archive_group[..], &[1]);
        assert_eq!(&refs.archive_member[..], &[1]);
        assert_eq!(refs.bytes[0], entry.bytes());
    }
}
