#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate std;

use mrml_error::{Result, anyhow};
use mrml_runtime::{
    MappedFile, Text, Vector, canonical_path, join_path, mrml_println as println, parent_path,
};
use mrml_rustc::{
    CodegenOptions, CoffObjectSymbolKind, CoffSectionIdentity, CoffShortImportKind,
    CoffTextComdatSelection, ElfSelectedDefinitions, ElfSelectedObject, ElfSelectedRelocations,
    ElfSelectedSections, LinkDefinition, LinkDefinitionTarget, LinkInput, LinkRelocation,
    LinkRelocationTarget, MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_SYMBOLS, MAX_LINK_DEFINITIONS,
    MAX_LINK_FRAGMENTS, MAX_LINK_INPUTS, MAX_LINK_RELOCATIONS, MAX_PE_READONLY_RELOCATIONS,
    MAX_PE_RUNTIME_FUNCTIONS, ObjectFormat, PeDataKind, PeReadonlyAbsoluteRelocation,
    PeRuntimeFunction, PeWritableData, PeWritableRelocation, PeWritableRelocationTarget,
    TargetLayout, compile_source_function_with_options, decode_unix_archive,
    decode_x86_64_coff_readonly_absolute_relocations_with_section_identities_from_inventory,
    decode_x86_64_coff_runtime_functions_with_section_identities,
    decode_x86_64_coff_section_identity_readonly_fragment,
    decode_x86_64_coff_short_import_with_alias,
    decode_x86_64_coff_text_fragment_with_section_identities_from_inventory,
    decode_x86_64_coff_writable_data_fragment_with_section_identities,
    decode_x86_64_elf_selected_definitions_from_sections,
    decode_x86_64_elf_selected_relocations_from_sections, decode_x86_64_elf_selected_sections,
    decode_x86_64_elf_with_definitions, inventory_x86_64_coff_comdat_sections,
    inventory_x86_64_coff_symbols, inventory_x86_64_elf_symbols,
    link_x86_64_elf_selected_executable,
    link_x86_64_pe_with_data_unwind_and_readonly_relocations_into_with_linked_scratch,
    select_ordered_static_link_members, select_x86_64_elf_link_sections_detailed,
    x86_64_coff_section_identity_readonly_fragment_count, x86_64_coff_short_import,
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
const MAX_PE_LINKED_BYTES: usize = 4 * 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_ELF_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_EXECUTABLE_BYTES: usize = 3 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmitKind {
    Object(ObjectFormat),
    Pe,
    ElfExecutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeCapacityTier {
    Tiny,
    Small,
    Medium,
    Large,
    Maximum,
}

struct LinkObjectRefs<'a> {
    bytes: Vector<&'a [u8]>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
    import_alias: Vector<Option<&'a str>>,
    archive_indexed: Vector<bool>,
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
    comdat_selection: Vector<CoffTextComdatSelection>,
    section_rebindings: Vector<CoffSectionRebinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoffSectionRebinding {
    discarded: CoffSectionIdentity,
    selected: CoffSectionIdentity,
}

fn resolve_duplicate_coff_definition(
    earlier: LinkInput<'_, '_, '_>,
    earlier_selection: CoffTextComdatSelection,
    current: LinkInput<'_, '_, '_>,
    current_selection: CoffTextComdatSelection,
) -> Option<(CoffTextComdatSelection, bool)> {
    let mut effective_selection = earlier_selection;
    let mut replace = false;
    let (earlier_payload, current_payload) = match (earlier.symbol_target, current.symbol_target) {
        (LinkDefinitionTarget::Text(0), LinkDefinitionTarget::Text(0)) => {
            (earlier.text, current.text)
        }
        (LinkDefinitionTarget::ReadonlyData(0), LinkDefinitionTarget::ReadonlyData(0)) => {
            (earlier.readonly_data, current.readonly_data)
        }
        _ => return None,
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
    compatible.then_some((effective_selection, replace))
}

fn typed_coff_input_section(
    input: LinkInput<'_, '_, '_>,
) -> Result<Option<(CoffSectionIdentity, bool)>> {
    let mut typed = None;
    for definition in core::iter::once(LinkDefinition {
        symbol: input.symbol,
        target: input.symbol_target,
    })
    .chain(input.additional_definitions.iter().copied())
    {
        let candidate = match definition.target {
            LinkDefinitionTarget::CoffTextSection { identity, .. } => Some((identity, true)),
            LinkDefinitionTarget::CoffSection { identity, .. } => Some((identity, false)),
            _ => None,
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if typed.replace(candidate).is_some() {
            return Err(anyhow!("link input defines multiple typed COFF sections"));
        }
    }
    Ok(typed)
}

fn record_coff_section_rebinding(
    rebindings: &mut Vector<CoffSectionRebinding>,
    earlier: LinkInput<'_, '_, '_>,
    current: LinkInput<'_, '_, '_>,
    replace: bool,
) -> Result<()> {
    let Some((earlier_identity, earlier_is_text)) = typed_coff_input_section(earlier)? else {
        return Ok(());
    };
    let Some((current_identity, current_is_text)) = typed_coff_input_section(current)? else {
        return Ok(());
    };
    if earlier_is_text != current_is_text {
        return Err(anyhow!(
            "duplicate COFF definitions use incompatible typed section kinds"
        ));
    }
    let (discarded, selected) = if replace {
        (earlier_identity, current_identity)
    } else {
        (current_identity, earlier_identity)
    };
    if discarded == selected {
        return Ok(());
    }
    for rebinding in rebindings.iter_mut() {
        if rebinding.selected == discarded {
            rebinding.selected = selected;
        }
    }
    if let Some(existing) = rebindings
        .iter()
        .find(|rebinding| rebinding.discarded == discarded)
    {
        if existing.selected != selected {
            return Err(anyhow!("conflicting selected COFF section rebinding"));
        }
        return Ok(());
    }
    rebindings
        .try_push(CoffSectionRebinding {
            discarded,
            selected,
        })
        .map_err(|_| anyhow!("selected COFF section rebinding capacity exceeded"))
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
            &object_refs.import_alias,
            &object_refs.archive_indexed,
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
            write_linked_pe(
                &[object.bytes()],
                &[0],
                &[0],
                &[None],
                &[true],
                function,
                output,
            )?;
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
            if !archive.has_symbol_index() || !thin_index_selection_safe {
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
    let mut import_alias = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link import-alias list"))?;
    let mut archive_indexed = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link index-presence list"))?;
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
            import_alias
                .try_push(None)
                .map_err(|_| anyhow!("could not allocate link import-alias list"))?;
            archive_indexed
                .try_push(true)
                .map_err(|_| anyhow!("could not allocate link index-presence list"))?;
        }
        if refs.is_empty() {
            return Err(anyhow!("link input list contains no object members"));
        }
        return Ok(LinkObjectRefs {
            bytes: refs,
            archive_group,
            archive_member,
            import_alias,
            archive_indexed,
        });
    }
    let mut referenced = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    let mut defined = Vector::with_capacity(MAX_ARCHIVE_SYMBOLS)
        .map_err(|_| anyhow!("could not allocate defined-symbol list"))?;
    referenced
        .try_push(entry)
        .map_err(|_| anyhow!("could not allocate unresolved-symbol list"))?;
    for object in objects {
        let object = object.as_ref();
        if object.get(..8) != Some(b"!<arch>\n") {
            scan_link_object_symbols(object, format, &mut referenced, &mut defined)?;
        }
    }
    let mut next_archive_group = 1u16;
    let mut indexed_selection_safe = true;
    for object in objects {
        let object = object.as_ref();
        if object.get(..8) == Some(b"!<arch>\n") {
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            let mut selected = [false; MAX_ARCHIVE_MEMBERS];
            if !archive.has_symbol_index() || !indexed_selection_safe {
                selected[..archive.members().len()].fill(true);
                indexed_selection_safe = false;
            } else {
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
                    let import_alias = short_import_alias(
                        format,
                        archive.members()[candidate.member_index].bytes,
                        archive.symbols(),
                        candidate.member_index,
                    )?;
                    if let Some(alias) = import_alias
                        && !defined.iter().any(|defined| *defined == alias)
                    {
                        defined
                            .try_push(alias)
                            .map_err(|_| anyhow!("defined-symbol capacity exceeded"))?;
                    }
                    if !defined.iter().any(|defined| *defined == candidate.symbol) {
                        return Err(anyhow!(
                            "archive group {} member {} ({}) symbol index for {} does not match its object member",
                            next_archive_group,
                            candidate.member_index + 1,
                            archive.members()[candidate.member_index].name,
                            candidate.symbol,
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
                import_alias
                    .try_push(short_import_alias(
                        format,
                        member.bytes,
                        archive.symbols(),
                        member_index,
                    )?)
                    .map_err(|_| anyhow!("could not allocate link import-alias list"))?;
                archive_indexed
                    .try_push(archive.has_symbol_index())
                    .map_err(|_| anyhow!("could not allocate link index-presence list"))?;
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
            import_alias
                .try_push(None)
                .map_err(|_| anyhow!("could not allocate link import-alias list"))?;
            archive_indexed
                .try_push(true)
                .map_err(|_| anyhow!("could not allocate link index-presence list"))?;
        }
    }
    loop {
        let mut changed = false;
        let mut group = 1u16;
        for object in objects {
            let object = object.as_ref();
            if object.get(..8) != Some(b"!<arch>\n") {
                continue;
            }
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            if archive.has_symbol_index() {
                let mut reference_cursor = 0usize;
                while reference_cursor < referenced.len() {
                    let symbol = referenced[reference_cursor];
                    reference_cursor += 1;
                    if defined.iter().any(|defined| *defined == symbol) {
                        continue;
                    }
                    let Some(candidate) = archive.symbols().iter().find(|candidate| {
                        candidate.symbol == symbol
                            && !archive_group.iter().zip(archive_member.iter()).any(
                                |(selected_group, selected_member)| {
                                    *selected_group == group
                                        && usize::from(*selected_member)
                                            == candidate.member_index + 1
                                },
                            )
                    }) else {
                        continue;
                    };
                    let member = &archive.members()[candidate.member_index];
                    scan_link_object_symbols(member.bytes, format, &mut referenced, &mut defined)
                        .map_err(|error| {
                        anyhow!(
                            "archive group {} member {} ({}) symbol inventory: {}",
                            group,
                            candidate.member_index + 1,
                            member.name,
                            error
                        )
                    })?;
                    let alias = short_import_alias(
                        format,
                        member.bytes,
                        archive.symbols(),
                        candidate.member_index,
                    )?;
                    if let Some(alias) = alias
                        && !defined.iter().any(|defined| *defined == alias)
                    {
                        defined
                            .try_push(alias)
                            .map_err(|_| anyhow!("defined-symbol capacity exceeded"))?;
                    }
                    if !defined.iter().any(|defined| *defined == candidate.symbol) {
                        return Err(anyhow!(
                            "archive group {} member {} ({}) symbol index for {} does not match its object member",
                            group,
                            candidate.member_index + 1,
                            member.name,
                            candidate.symbol,
                        ));
                    }
                    if refs.len() == MAX_LINK_INPUTS {
                        return Err(anyhow!("expanded link input count exceeds 256"));
                    }
                    refs.try_push(member.bytes)
                        .map_err(|_| anyhow!("could not allocate link input reference list"))?;
                    archive_group
                        .try_push(group)
                        .map_err(|_| anyhow!("could not allocate link input origin list"))?;
                    archive_member
                        .try_push(
                            u16::try_from(candidate.member_index + 1)
                                .map_err(|_| anyhow!("archive member identity overflow"))?,
                        )
                        .map_err(|_| anyhow!("could not allocate link member origin list"))?;
                    import_alias
                        .try_push(alias)
                        .map_err(|_| anyhow!("could not allocate link import-alias list"))?;
                    archive_indexed
                        .try_push(true)
                        .map_err(|_| anyhow!("could not allocate link index-presence list"))?;
                    changed = true;
                }
            }
            group = group
                .checked_add(1)
                .ok_or_else(|| anyhow!("archive group identity overflow"))?;
        }
        if !changed {
            break;
        }
    }

    let selected_group = archive_group;
    let selected_member = archive_member;
    let mut ordered_refs = Vector::with_capacity(refs.len())
        .map_err(|_| anyhow!("could not allocate ordered link input reference list"))?;
    let mut ordered_group = Vector::with_capacity(refs.len())
        .map_err(|_| anyhow!("could not allocate ordered link input origin list"))?;
    let mut ordered_member = Vector::with_capacity(refs.len())
        .map_err(|_| anyhow!("could not allocate ordered link member origin list"))?;
    let mut ordered_alias = Vector::with_capacity(refs.len())
        .map_err(|_| anyhow!("could not allocate ordered link import-alias list"))?;
    let mut ordered_indexed = Vector::with_capacity(refs.len())
        .map_err(|_| anyhow!("could not allocate ordered link index-presence list"))?;
    let mut group = 1u16;
    for object in objects {
        let object = object.as_ref();
        if object.get(..8) == Some(b"!<arch>\n") {
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            for (member_index, member) in archive.members().iter().enumerate() {
                let member_number = u16::try_from(member_index + 1)
                    .map_err(|_| anyhow!("archive member identity overflow"))?;
                if member.name == "lib.rmeta"
                    || member.name == "lib.rmeta-link"
                    || !selected_group.iter().zip(selected_member.iter()).any(
                        |(selected_group, selected_member)| {
                            *selected_group == group && *selected_member == member_number
                        },
                    )
                {
                    continue;
                }
                ordered_refs
                    .try_push(member.bytes)
                    .map_err(|_| anyhow!("could not allocate ordered link input list"))?;
                ordered_group
                    .try_push(group)
                    .map_err(|_| anyhow!("could not allocate ordered link origin list"))?;
                ordered_member
                    .try_push(member_number)
                    .map_err(|_| anyhow!("could not allocate ordered link member list"))?;
                ordered_alias
                    .try_push(short_import_alias(
                        format,
                        member.bytes,
                        archive.symbols(),
                        member_index,
                    )?)
                    .map_err(|_| anyhow!("could not allocate ordered import-alias list"))?;
                ordered_indexed
                    .try_push(archive.has_symbol_index())
                    .map_err(|_| anyhow!("could not allocate ordered index-presence list"))?;
            }
            group = group
                .checked_add(1)
                .ok_or_else(|| anyhow!("archive group identity overflow"))?;
        } else {
            ordered_refs
                .try_push(object)
                .map_err(|_| anyhow!("could not allocate ordered link input list"))?;
            ordered_group
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate ordered link origin list"))?;
            ordered_member
                .try_push(0)
                .map_err(|_| anyhow!("could not allocate ordered link member list"))?;
            ordered_alias
                .try_push(None)
                .map_err(|_| anyhow!("could not allocate ordered import-alias list"))?;
            ordered_indexed
                .try_push(true)
                .map_err(|_| anyhow!("could not allocate ordered index-presence list"))?;
        }
    }
    refs = ordered_refs;
    archive_group = ordered_group;
    archive_member = ordered_member;
    import_alias = ordered_alias;
    archive_indexed = ordered_indexed;
    if refs.is_empty() {
        return Err(anyhow!("link input list contains no object members"));
    }
    Ok(LinkObjectRefs {
        bytes: refs,
        archive_group,
        archive_member,
        import_alias,
        archive_indexed,
    })
}

fn short_import_alias<'a>(
    format: ObjectFormat,
    object: &[u8],
    symbols: &[mrml_rustc::ArchiveSymbol<'a>],
    member_index: usize,
) -> Result<Option<&'a str>> {
    if format != ObjectFormat::Coff {
        return Ok(None);
    }
    let Some(import) = x86_64_coff_short_import(object).map_err(mrml_error::message)? else {
        return Ok(None);
    };
    Ok(symbols.iter().find_map(|candidate| {
        (candidate.member_index == member_index
            && candidate.symbol.strip_prefix("__imp_") == Some(import.symbol))
        .then_some(candidate.symbol)
    }))
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
    object_import_alias: &[Option<&'data str>],
    format: ObjectFormat,
    relocation_arenas: &'relocations mut [[LinkRelocation<'data>; MAX_LINK_RELOCATIONS]],
    definition_arenas: &'definitions mut [[LinkDefinition<'data>; MAX_LINK_DEFINITIONS]],
) -> Result<DecodedLinkInputs<'data, 'relocations, 'definitions>> {
    if objects.len() != object_archive_group.len()
        || objects.len() != object_archive_member.len()
        || objects.len() != object_import_alias.len()
    {
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
            ObjectFormat::Coff => x86_64_coff_short_import(object)
                .map_err(|error| anyhow!("COFF object {} short import: {}", object_index, error))?,
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
                    "COFF object {} archive group {} member {} text fragment count: {}",
                    object_index,
                    object_archive_group[object_index],
                    object_archive_member[object_index],
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
                ObjectFormat::Coff if coff_short_import.is_some() => {
                    let mut input = decode_x86_64_coff_short_import_with_alias(
                        object,
                        object_import_alias[object_index],
                        arena,
                    )
                    .map_err(|error| {
                        anyhow!(
                            "COFF object {} short import decode: {}",
                            object_index,
                            error
                        )
                    })?
                    .ok_or_else(|| anyhow!("COFF short import changed after inventory"))?;
                    if coff_short_import
                        .is_some_and(|import| import.kind == CoffShortImportKind::Code)
                        && let Some(alias) = object_import_alias[object_index]
                    {
                        definitions[0] = LinkDefinition {
                            symbol: alias,
                            target: LinkDefinitionTarget::PeImportAddress,
                        };
                        input.additional_definitions = &definitions[..1];
                    }
                    (input, CoffTextComdatSelection::None)
                }
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

fn expanded_fragment_count(
    objects: &[&[u8]],
    archive_group: &[u16],
    archive_member: &[u16],
    format: ObjectFormat,
) -> Result<usize> {
    if objects.len() != archive_group.len() || objects.len() != archive_member.len() {
        return Err(anyhow!("link input origin count mismatch"));
    }
    let mut count = 0usize;
    for (object_index, object) in objects.iter().enumerate() {
        let object_fragments =
            match format {
                ObjectFormat::Coff => {
                    if x86_64_coff_short_import(object)
                        .map_err(|error| {
                            anyhow!("COFF object {} short import: {}", object_index, error)
                        })?
                        .is_some()
                    {
                        1
                    } else {
                        let inventory =
                            inventory_x86_64_coff_comdat_sections(object).map_err(|error| {
                                anyhow!("COFF object {} COMDAT inventory: {}", object_index, error)
                            })?;
                        x86_64_coff_text_fragment_count(object)
                    .map_err(|error| {
                        anyhow!(
                            "COFF object {} archive group {} member {} text fragment count: {}",
                            object_index, archive_group[object_index], archive_member[object_index],
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
        Vector::with_capacity(inputs.len())
            .map_err(|_| anyhow!("could not allocate selected link input list"))?;
    let mut selected_group = Vector::with_capacity(inputs.len())
        .map_err(|_| anyhow!("could not allocate selected link origin list"))?;
    let mut selected_member = Vector::with_capacity(inputs.len())
        .map_err(|_| anyhow!("could not allocate selected link member list"))?;
    let mut selected_comdat = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected COMDAT list"))?;
    let mut section_rebindings = Vector::with_capacity(inputs.len())
        .map_err(|_| anyhow!("could not allocate selected COFF section rebindings"))?;
    let mut selected_source_object = Vector::with_capacity(inputs.len())
        .map_err(|_| anyhow!("could not allocate selected source-object list"))?;
    for index in selection.indices() {
        let current_is_internal = matches!(
            inputs[*index].symbol_target,
            LinkDefinitionTarget::CoffTextSection { .. } | LinkDefinitionTarget::CoffSection { .. }
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
            if let Some((effective_selection, replace)) = resolve_duplicate_coff_definition(
                selected[earlier],
                earlier_selection,
                inputs[*index],
                current_selection,
            ) {
                record_coff_section_rebinding(
                    &mut section_rebindings,
                    selected[earlier],
                    inputs[*index],
                    replace,
                )?;
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
        comdat_selection: selected_comdat,
        section_rebindings,
    })
}

fn retain_exact_readonly_relocation_targets<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    source_object: &[usize],
    comdat_selection: &[CoffTextComdatSelection],
    selected: &mut SelectedLinkInputs<'data, 'relocations, 'definitions>,
    relocations: &[PeReadonlyAbsoluteRelocation<'_>],
) -> Result<bool> {
    if inputs.len() != archive_group.len()
        || inputs.len() != archive_member.len()
        || inputs.len() != source_object.len()
        || inputs.len() != comdat_selection.len()
    {
        return Err(anyhow!("decoded exact-section origin count mismatch"));
    }
    let mut changed = false;
    for relocation in relocations {
        let Some(identity) = relocation.target_identity else {
            continue;
        };
        let already_selected = selected.inputs.iter().any(|input| {
            matches!(input.symbol_target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                || input.additional_definitions.iter().any(|definition| {
                    matches!(definition.target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                })
        });
        if already_selected {
            continue;
        }
        let Some(index) = inputs.iter().position(|input| {
            matches!(input.symbol_target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                || input.additional_definitions.iter().any(|definition| {
                    matches!(definition.target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                })
        }) else {
            continue;
        };
        changed |= retain_input_archive_member(
            inputs,
            archive_group,
            archive_member,
            source_object,
            comdat_selection,
            selected,
            index,
        )?;
    }
    Ok(changed)
}

fn retain_input_archive_member<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    source_object: &[usize],
    comdat_selection: &[CoffTextComdatSelection],
    selected: &mut SelectedLinkInputs<'data, 'relocations, 'definitions>,
    target_index: usize,
) -> Result<bool> {
    if inputs.len() != archive_group.len()
        || inputs.len() != archive_member.len()
        || inputs.len() != source_object.len()
        || inputs.len() != comdat_selection.len()
    {
        return Err(anyhow!("decoded archive member projection count mismatch"));
    }
    let group = archive_group[target_index];
    let member = archive_member[target_index];
    let mut changed = false;
    for index in 0..inputs.len() {
        if if group == 0 {
            index != target_index
        } else {
            archive_group[index] != group || archive_member[index] != member
        } {
            continue;
        }
        if selected
            .inputs
            .iter()
            .zip(selected.source_object.iter())
            .any(|(selected_input, selected_source)| {
                *selected_source == source_object[index]
                    && selected_input.symbol == inputs[index].symbol
                    && selected_input.symbol_target == inputs[index].symbol_target
                    && selected_input.text.as_ptr() == inputs[index].text.as_ptr()
                    && selected_input.text.len() == inputs[index].text.len()
            })
        {
            continue;
        }
        let current_is_internal = matches!(
            inputs[index].symbol_target,
            LinkDefinitionTarget::CoffTextSection { .. } | LinkDefinitionTarget::CoffSection { .. }
        );
        if let Some(earlier) = (!current_is_internal)
            .then(|| {
                selected.inputs.iter().position(|candidate| {
                    !matches!(
                        candidate.symbol_target,
                        LinkDefinitionTarget::CoffTextSection { .. }
                            | LinkDefinitionTarget::CoffSection { .. }
                    ) && candidate.symbol == inputs[index].symbol
                })
            })
            .flatten()
        {
            let earlier_selection = selected.comdat_selection[earlier];
            let current_selection = comdat_selection[index];
            let earlier_input = selected.inputs[earlier];
            let Some((effective_selection, replace)) = resolve_duplicate_coff_definition(
                earlier_input,
                earlier_selection,
                inputs[index],
                current_selection,
            ) else {
                return Err(anyhow!(
                    "incompatible retained COFF definition {}: source object {} uses {:?}, source object {} uses {:?}",
                    inputs[index].symbol,
                    selected.source_object[earlier],
                    earlier_selection,
                    source_object[index],
                    current_selection
                ));
            };
            record_coff_section_rebinding(
                &mut selected.section_rebindings,
                earlier_input,
                inputs[index],
                replace,
            )?;
            if replace {
                selected.inputs[earlier] = inputs[index];
                selected.archive_group[earlier] = archive_group[index];
                selected.archive_member[earlier] = archive_member[index];
                selected.source_object[earlier] = source_object[index];
                changed = true;
            }
            selected.comdat_selection[earlier] = effective_selection;
            continue;
        }
        selected
            .inputs
            .try_push(inputs[index])
            .map_err(|_| anyhow!("selected archive dependency capacity exceeded"))?;
        selected
            .archive_group
            .try_push(archive_group[index])
            .map_err(|_| anyhow!("selected archive origin capacity exceeded"))?;
        selected
            .archive_member
            .try_push(archive_member[index])
            .map_err(|_| anyhow!("selected archive member capacity exceeded"))?;
        selected
            .source_object
            .try_push(source_object[index])
            .map_err(|_| anyhow!("selected archive source capacity exceeded"))?;
        selected
            .comdat_selection
            .try_push(comdat_selection[index])
            .map_err(|_| anyhow!("selected archive COMDAT capacity exceeded"))?;
        changed = true;
    }
    Ok(changed)
}

fn retain_named_code_targets<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    source_object: &[usize],
    comdat_selection: &[CoffTextComdatSelection],
    selected: &mut SelectedLinkInputs<'data, 'relocations, 'definitions>,
    frontier_start: usize,
) -> Result<bool> {
    let mut targets = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate named archive dependency frontier"))?;
    let frontier_end = selected.inputs.len();
    let frontier = selected
        .inputs
        .get(frontier_start..frontier_end)
        .ok_or_else(|| anyhow!("named archive dependency frontier is invalid"))?;
    for input in frontier {
        for relocation in input.relocations {
            let symbol = match relocation.target {
                LinkRelocationTarget::Symbol(symbol)
                | LinkRelocationTarget::GotPcRelativeSymbol(symbol)
                | LinkRelocationTarget::RequiredSymbol(symbol) => symbol,
                _ => continue,
            };
            let already_defined = selected.inputs.iter().any(|input| {
                core::iter::once(LinkDefinition {
                    symbol: input.symbol,
                    target: input.symbol_target,
                })
                .chain(input.additional_definitions.iter().copied())
                .any(|definition| {
                    definition.symbol == symbol
                        && !matches!(
                            definition.target,
                            LinkDefinitionTarget::CoffTextSection { .. }
                                | LinkDefinitionTarget::CoffSection { .. }
                        )
                })
            });
            if already_defined {
                continue;
            }
            let Some(target) = inputs.iter().position(|input| {
                core::iter::once(LinkDefinition {
                    symbol: input.symbol,
                    target: input.symbol_target,
                })
                .chain(input.additional_definitions.iter().copied())
                .any(|definition| {
                    definition.symbol == symbol
                        && !matches!(
                            definition.target,
                            LinkDefinitionTarget::CoffTextSection { .. }
                                | LinkDefinitionTarget::CoffSection { .. }
                        )
                })
            }) else {
                continue;
            };
            let same_member = |candidate: usize| {
                if archive_group[target] == 0 {
                    candidate == target
                } else {
                    archive_group[candidate] == archive_group[target]
                        && archive_member[candidate] == archive_member[target]
                }
            };
            if targets.iter().copied().any(same_member) {
                continue;
            }
            targets
                .try_push(target)
                .map_err(|_| anyhow!("named archive dependency frontier capacity exceeded"))?;
        }
    }
    let mut changed = false;
    for target in targets {
        changed |= retain_input_archive_member(
            inputs,
            archive_group,
            archive_member,
            source_object,
            comdat_selection,
            selected,
            target,
        )?;
    }
    Ok(changed)
}

fn retain_writable_section_targets<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    source_object: &[usize],
    comdat_selection: &[CoffTextComdatSelection],
    selected: &mut SelectedLinkInputs<'data, 'relocations, 'definitions>,
    writable_data: &[PeWritableData<'_, '_>],
) -> Result<bool> {
    let mut changed = false;
    for relocation in writable_data.iter().flat_map(|data| data.relocations) {
        if let PeWritableRelocationTarget::CoffSection { identity, .. } = relocation.target {
            let already_selected = selected.inputs.iter().any(|input| {
                matches!(input.symbol_target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                    || input.additional_definitions.iter().any(|definition| {
                        matches!(definition.target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                    })
            });
            if already_selected {
                continue;
            }
            let Some(target_index) = inputs.iter().position(|input| {
                matches!(input.symbol_target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                    || input.additional_definitions.iter().any(|definition| {
                        matches!(definition.target, LinkDefinitionTarget::CoffTextSection { identity: candidate, .. } | LinkDefinitionTarget::CoffSection { identity: candidate, .. } if candidate == identity)
                    })
            }) else {
                continue;
            };
            changed |= retain_input_archive_member(
                inputs,
                archive_group,
                archive_member,
                source_object,
                comdat_selection,
                selected,
                target_index,
            )?;
        }
    }
    Ok(changed)
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
            if x86_64_coff_short_import(objects[object_index])
                .map_err(|error| {
                    anyhow!(
                        "COFF object {} selected short import: {}",
                        object_index,
                        error
                    )
                })?
                .is_some()
            {
                continue;
            }
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
            })? {
                let retained = selected
                    .inputs
                    .iter()
                    .zip(selected.source_object.iter())
                    .any(|(input, source)| {
                        if *source != object_index {
                            return false;
                        }
                        match function.begin_identity {
                            Some(identity) => {
                                matches!(
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
                                })
                            }
                            None => {
                                input.symbol == function.begin_symbol
                                    || input.additional_definitions.iter().any(|definition| {
                                        definition.symbol == function.begin_symbol
                                    })
                            }
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
    for (object_index, object) in objects.iter().enumerate() {
        if x86_64_coff_short_import(object)
            .map_err(|error| {
                anyhow!(
                    "COFF object {} writable short import: {}",
                    object_index,
                    error
                )
            })?
            .is_some()
        {
            continue;
        }
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
    archive_indexed: &[bool],
    selected: &SelectedLinkInputs<'data, '_, '_>,
    arenas: &'relocations mut [[PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS]],
) -> Result<Vector<PeWritableData<'data, 'relocations>>> {
    if objects.len() != archive_indexed.len() {
        return Err(anyhow!("link index-presence count mismatch"));
    }
    let mut output = Vector::with_capacity(arenas.len())
        .map_err(|_| anyhow!("could not allocate selected writable data list"))?;
    let mut remaining = arenas;
    for object_index in 0..objects.len() {
        if x86_64_coff_short_import(objects[object_index])
            .map_err(|error| {
                anyhow!(
                    "COFF object {} selected writable short import: {}",
                    object_index,
                    error
                )
            })?
            .is_some()
        {
            continue;
        }
        let group = archive_group[object_index];
        let member = archive_member[object_index];
        let mut owner = selected
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
        if owner.is_none() && archive_indexed[object_index] {
            let inventory =
                inventory_x86_64_coff_symbols(objects[object_index]).map_err(|error| {
                    anyhow!("COFF object {} symbol inventory: {}", object_index, error)
                })?;
            for symbol in inventory.symbols() {
                let symbol = symbol.map_err(|error| {
                    anyhow!("COFF object {} symbol inventory: {}", object_index, error)
                })?;
                if symbol.kind == CoffObjectSymbolKind::Definition {
                    owner = Some(symbol.name);
                    break;
                }
            }
        }
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

fn selected_coff_section_length(
    selected: &SelectedLinkInputs<'_, '_, '_>,
    identity: CoffSectionIdentity,
) -> Result<Option<usize>> {
    let mut length = None;
    for input in &selected.inputs {
        let Some((candidate, is_text)) = typed_coff_input_section(*input)? else {
            continue;
        };
        if candidate != identity {
            continue;
        }
        if length.is_some() {
            return Err(anyhow!("selected COFF section identity is ambiguous"));
        }
        length = Some(if is_text {
            input.text.len()
        } else {
            input.readonly_data.len()
        });
    }
    Ok(length)
}

fn rebind_selected_readonly_comdat_target<'data>(
    selected: &SelectedLinkInputs<'data, '_, '_>,
    relocation: PeReadonlyAbsoluteRelocation<'data>,
) -> Result<PeReadonlyAbsoluteRelocation<'data>> {
    let Some(original) = relocation.target_identity else {
        return Ok(relocation);
    };
    if selected_coff_section_length(selected, original)?.is_some() {
        return Ok(relocation);
    }
    let mut rebound = original;
    for _ in 0..selected.section_rebindings.len() {
        let Some(rebinding) = selected
            .section_rebindings
            .iter()
            .find(|candidate| candidate.discarded == rebound)
        else {
            break;
        };
        rebound = rebinding.selected;
    }
    if rebound == original {
        return Ok(relocation);
    }
    if selected
        .section_rebindings
        .iter()
        .any(|candidate| candidate.discarded == rebound)
    {
        return Err(anyhow!("selected COFF section rebinding contains a cycle"));
    }
    let selected_length = selected_coff_section_length(selected, rebound)?.ok_or_else(|| {
        anyhow!(
            "selected COFF section rebinding target is undefined: object {}, section {}",
            rebound.object(),
            rebound.section()
        )
    })?;
    if relocation.target_offset > selected_length {
        return Err(anyhow!(
            "selected COFF section rebinding offset exceeds its target"
        ));
    }
    Ok(PeReadonlyAbsoluteRelocation {
        target_identity: Some(rebound),
        ..relocation
    })
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
            if x86_64_coff_short_import(objects[object_index])
                .map_err(|error| {
                    anyhow!(
                        "COFF object {} selected read-only short import: {}",
                        object_index,
                        error
                    )
                })?
                .is_some()
            {
                continue;
            }
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
                let retained = selected
                    .inputs
                    .iter()
                    .zip(selected.source_object.iter())
                    .any(|(input, source)| {
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
                    });
                if retained {
                    if output.len() == MAX_PE_READONLY_RELOCATIONS {
                        return Err(anyhow!("too many selected COFF readonly relocations"));
                    }
                    let relocation = rebind_selected_readonly_comdat_target(selected, *relocation)?;
                    output
                        .try_push(relocation)
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
    let writable_target_defined =
        |symbol: &str| writable_data.iter().any(|data| data.symbol == symbol);
    let typed_section_target = |symbol: &str| {
        inputs.iter().find_map(|input| {
            core::iter::once(LinkDefinition {
                symbol: input.symbol,
                target: input.symbol_target,
            })
            .chain(input.additional_definitions.iter().copied())
            .find_map(|definition| {
                if definition.symbol != symbol {
                    return None;
                }
                match definition.target {
                    LinkDefinitionTarget::CoffTextSection { identity, offset }
                    | LinkDefinitionTarget::CoffSection { identity, offset } => {
                        Some((identity, offset))
                    }
                    _ => None,
                }
            })
        })
    };
    let import_target = |symbol: &str| {
        inputs.iter().find_map(|input| {
            let defines_import = (input.symbol == symbol
                && input.symbol_target == LinkDefinitionTarget::PeImportAddress)
                || input.additional_definitions.iter().any(|definition| {
                    definition.symbol == symbol
                        && definition.target == LinkDefinitionTarget::PeImportAddress
                });
            defines_import.then(|| {
                input
                    .relocations
                    .iter()
                    .find_map(|relocation| match relocation.target {
                        LinkRelocationTarget::PeImportAddress { library, symbol }
                        | LinkRelocationTarget::PeImportMetadata { library, symbol } => {
                            Some((library, symbol))
                        }
                        _ => None,
                    })
            })?
        })
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
                LinkRelocationTarget::Symbol(symbol) => {
                    if let Some((identity, offset)) = typed_section_target(symbol) {
                        LinkRelocation {
                            target: LinkRelocationTarget::CoffSection { identity, offset },
                            ..relocation
                        }
                    } else if let Some((library, import)) = import_target(symbol) {
                        LinkRelocation {
                            target: LinkRelocationTarget::PeImportAddress {
                                library,
                                symbol: import,
                            },
                            ..relocation
                        }
                    } else if !link_target_defined(symbol) && writable_target_defined(symbol) {
                        LinkRelocation {
                            target: LinkRelocationTarget::PeWritableSymbol(symbol),
                            ..relocation
                        }
                    } else {
                        relocation
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
    import_alias: &[Option<&str>],
    archive_indexed: &[bool],
    entry: &str,
    output: &str,
) -> Result<()> {
    let fragment_count =
        expanded_fragment_count(objects, archive_group, archive_member, ObjectFormat::Coff)?;
    let mut arenas = relocation_arenas(fragment_count)?;
    let mut definitions = definition_arenas(fragment_count)?;
    let decoded = decode_link_inputs(
        objects,
        archive_group,
        archive_member,
        import_alias,
        ObjectFormat::Coff,
        &mut arenas,
        &mut definitions,
    )?;
    let mut selected = selected_link_inputs(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        &decoded.source_object,
        &decoded.comdat_selection,
        entry,
    )?;
    loop {
        let readonly_absolute_relocations = selected_readonly_absolute_relocations(
            objects,
            archive_group,
            archive_member,
            &selected,
        )?;
        if !retain_exact_readonly_relocation_targets(
            &decoded.inputs,
            &decoded.archive_group,
            &decoded.archive_member,
            &decoded.source_object,
            &decoded.comdat_selection,
            &mut selected,
            &readonly_absolute_relocations,
        )? {
            break;
        }
    }
    let writable_count = writable_fragment_count(objects)?;
    let mut probe_writable_arenas = writable_relocation_arenas(writable_count)?;
    let probe_writable_data = selected_writable_data(
        objects,
        archive_group,
        archive_member,
        archive_indexed,
        &selected,
        &mut probe_writable_arenas,
    )?;
    let writable_frontier_start = selected.inputs.len();
    retain_writable_section_targets(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        &decoded.source_object,
        &decoded.comdat_selection,
        &mut selected,
        &probe_writable_data,
    )?;
    drop(probe_writable_data);
    let named_frontier_start = selected.inputs.len();
    retain_named_code_targets(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        &decoded.source_object,
        &decoded.comdat_selection,
        &mut selected,
        writable_frontier_start,
    )?;
    retain_named_code_targets(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        &decoded.source_object,
        &decoded.comdat_selection,
        &mut selected,
        named_frontier_start,
    )?;
    loop {
        let readonly_absolute_relocations = selected_readonly_absolute_relocations(
            objects,
            archive_group,
            archive_member,
            &selected,
        )?;
        if !retain_exact_readonly_relocation_targets(
            &decoded.inputs,
            &decoded.archive_group,
            &decoded.archive_member,
            &decoded.source_object,
            &decoded.comdat_selection,
            &mut selected,
            &readonly_absolute_relocations,
        )? {
            break;
        }
    }
    let readonly_absolute_relocations =
        selected_readonly_absolute_relocations(objects, archive_group, archive_member, &selected)?;
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
    let mut writable_arenas = writable_relocation_arenas(writable_count)?;
    let writable_data = selected_writable_data(
        objects,
        archive_group,
        archive_member,
        archive_indexed,
        &selected,
        &mut writable_arenas,
    )?;
    let mut contextual_arenas = relocation_arenas(selected.inputs.len())?;
    let contextual_inputs = contextualize_pe_writable_relocations(
        &selected.inputs,
        &writable_data,
        &mut contextual_arenas,
    )?;
    let payload = selected_payload_bound(&contextual_inputs, &runtime_functions, &writable_data)?;
    match pe_capacity_tier(payload) {
        PeCapacityTier::Tiny => write_pe_image::<{ 32 * 1024 }, { 16 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        ),
        PeCapacityTier::Small => write_pe_image::<{ 512 * 1024 }, { 256 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        ),
        PeCapacityTier::Medium => write_pe_image::<{ 1024 * 1024 }, { 512 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        ),
        PeCapacityTier::Large => write_pe_image::<{ 768 * 1024 }, { 768 * 1024 }>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        ),
        PeCapacityTier::Maximum => write_pe_image::<MAX_EXECUTABLE_BYTES, MAX_PE_LINKED_BYTES>(
            &contextual_inputs,
            &runtime_functions,
            &writable_data,
            &readonly_absolute_relocations,
            entry,
            output,
        ),
    }
}

fn pe_capacity_tier(payload: usize) -> PeCapacityTier {
    if payload <= 16 * 1024 {
        PeCapacityTier::Tiny
    } else if payload <= 256 * 1024 {
        PeCapacityTier::Small
    } else if payload <= 512 * 1024 {
        PeCapacityTier::Medium
    } else if payload <= 768 * 1024 {
        PeCapacityTier::Large
    } else {
        PeCapacityTier::Maximum
    }
}

fn global_link_definitions<'input, 'data, 'relocations, 'definitions>(
    input: &'input LinkInput<'data, 'relocations, 'definitions>,
) -> impl Iterator<Item = LinkDefinition<'data>> + 'input
where
    'data: 'input,
    'definitions: 'input,
{
    core::iter::once(LinkDefinition {
        symbol: input.symbol,
        target: input.symbol_target,
    })
    .chain(input.additional_definitions.iter().copied())
    .filter(|definition| {
        !matches!(
            definition.target,
            LinkDefinitionTarget::CoffTextSection { .. } | LinkDefinitionTarget::CoffSection { .. }
        )
    })
}

fn duplicate_global_link_symbol<'data>(inputs: &[LinkInput<'data, '_, '_>]) -> Option<&'data str> {
    for (input_index, input) in inputs.iter().enumerate() {
        for (definition_index, definition) in global_link_definitions(input).enumerate() {
            let defined_earlier = inputs[..input_index].iter().any(|earlier| {
                global_link_definitions(earlier)
                    .any(|candidate| candidate.symbol == definition.symbol)
            }) || global_link_definitions(input)
                .take(definition_index)
                .any(|candidate| candidate.symbol == definition.symbol);
            if defined_earlier {
                return Some(definition.symbol);
            }
        }
    }
    None
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
    let writable_target_defined =
        |symbol: &str| writable_data.iter().any(|data| data.symbol == symbol);
    let writable_section_defined = |identity: CoffSectionIdentity| {
        writable_data
            .iter()
            .any(|data| data.identity == Some(identity))
    };
    let tls_section_defined = |identity: CoffSectionIdentity| {
        writable_data
            .iter()
            .any(|data| matches!(data.kind, PeDataKind::Tls(_)) && data.identity == Some(identity))
    };
    let named_target_defined =
        |symbol: &str| link_target_defined(symbol) || writable_target_defined(symbol);
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
        if relocation.target_identity.is_none() && !named_target_defined(relocation.target_symbol) {
            return Err(anyhow!(
                "selected read-only relocation target is undefined: {}",
                relocation.target_symbol
            ));
        }
        if let Some(identity) = relocation.target_identity
            && !section_identity_defined(identity)
            && !writable_section_defined(identity)
        {
            return Err(anyhow!(
                "selected read-only relocation target section is undefined: {} (object {}, section {})",
                relocation.target_symbol,
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
                let kind = match relocation.target {
                    LinkRelocationTarget::Symbol(_) => "symbol",
                    LinkRelocationTarget::GotPcRelativeSymbol(_) => "GOT-relative symbol",
                    LinkRelocationTarget::RequiredSymbol(_) => "required symbol",
                    LinkRelocationTarget::LocalSymbol(_) => "local symbol",
                    _ => unreachable!(),
                };
                return Err(anyhow!(
                    "selected code relocation {} target is undefined: {}",
                    kind,
                    symbol,
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
            if let LinkRelocationTarget::PeWritableSection { identity, .. } = relocation.target
                && !writable_section_defined(identity)
            {
                return Err(anyhow!(
                    "selected code relocation writable section is undefined: object {}, section {}",
                    identity.object(),
                    identity.section()
                ));
            }
            if let LinkRelocationTarget::PeTlsSection { identity, .. } = relocation.target
                && !tls_section_defined(identity)
            {
                return Err(anyhow!(
                    "selected PE TLS target section is undefined: object {}, section {}",
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
                PeWritableRelocationTarget::TextSymbol(symbol) if !named_target_defined(symbol) => {
                    return Err(anyhow!(
                        "selected writable relocation text target is undefined: {}",
                        symbol
                    ));
                }
                PeWritableRelocationTarget::TlsSection { identity, .. }
                    if !tls_section_defined(identity) =>
                {
                    return Err(anyhow!(
                        "selected writable PE TLS target section is undefined: object {}, section {}",
                        identity.object(),
                        identity.section()
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
    if let Some(symbol) = duplicate_global_link_symbol(inputs) {
        return Err(anyhow!(
            "selected link symbol is defined more than once: {}",
            symbol
        ));
    }
    let mut linked_scratch = Vector::with_capacity(MAX_LINKED)
        .map_err(|_| anyhow!("could not allocate bounded PE linked-image scratch"))?;
    linked_scratch
        .try_resize(MAX_LINKED, 0)
        .map_err(|_| anyhow!("could not initialize bounded PE linked-image scratch"))?;
    let mut executable = Vector::with_capacity(MAX_IMAGE)
        .map_err(|_| anyhow!("could not allocate bounded PE image output"))?;
    executable
        .try_resize(MAX_IMAGE, 0)
        .map_err(|_| anyhow!("could not initialize bounded PE image output"))?;
    let code_relocation_count = inputs.iter().try_fold(0usize, |count, input| {
        count
            .checked_add(input.relocations.len())
            .ok_or_else(|| anyhow!("selected code relocation count overflow"))
    })?;
    let length =
        link_x86_64_pe_with_data_unwind_and_readonly_relocations_into_with_linked_scratch(
            inputs,
            entry,
            runtime_functions,
            writable_data,
            readonly_absolute_relocations,
            &mut executable,
            &mut linked_scratch,
        )
        .map_err(|error| {
            anyhow!(
                "could not serialize linked PE image: {} (code relocations {}, runtime functions {}, read-only relocations {})",
                error,
                code_relocation_count,
                runtime_functions.len(),
                readonly_absolute_relocations.len()
            )
        })?;
    mrml_runtime::write_file(output, &executable[..length])?;
    println!("linked {} to {} deterministic PE bytes", entry, length);
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
    write_selected_elf_image::<MAX_EXECUTABLE_BYTES, MAX_ELF_PAYLOAD_BYTES>(
        &selected, entry, output,
    )
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

    fn short_import_object() -> std::vec::Vec<u8> {
        let payload = b"WaitOnAddress\0api-ms-win-core-synch-l1-2-0.dll\0";
        let mut object = std::vec![0u8; 20 + payload.len()];
        object[..4].copy_from_slice(b"\0\0\xff\xff");
        object[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
        object[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        object[18..20].copy_from_slice(&4u16.to_le_bytes());
        object[20..].copy_from_slice(payload);
        object
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
    fn excludes_validated_short_imports_from_coff_data_metadata() {
        let import = short_import_object();
        assert!(x86_64_coff_short_import(&import).unwrap().is_some());
        assert_eq!(writable_fragment_count(&[&import]).unwrap(), 0);

        let mut archive = Vector::with_capacity(1024).unwrap();
        archive.try_extend_from_slice(b"!<arch>\n").unwrap();
        let mut index = std::vec![0, 0, 0, 1, 0, 0, 0, 0];
        index.extend_from_slice(b"__imp_WaitOnAddress\0");
        let member_offset = u32::try_from(8 + 60 + index.len()).unwrap();
        index[4..8].copy_from_slice(&member_offset.to_be_bytes());
        append_archive_member(&mut archive, "/", &index);
        append_archive_member(&mut archive, "import.o/", &import);
        let archives = [archive];
        let refs = link_object_refs(&archives, ObjectFormat::Coff, "__imp_WaitOnAddress").unwrap();
        assert_eq!(&refs.import_alias[..], &[Some("__imp_WaitOnAddress")]);

        let mut data_import = short_import_object();
        data_import[18..20].copy_from_slice(&5u16.to_le_bytes());
        let mut data_archive = Vector::with_capacity(1024).unwrap();
        data_archive.try_extend_from_slice(b"!<arch>\n").unwrap();
        append_archive_member(&mut data_archive, "/", &index);
        append_archive_member(&mut data_archive, "import.o/", &data_import);
        let data_archives = [data_archive];
        let data_refs =
            link_object_refs(&data_archives, ObjectFormat::Coff, "__imp_WaitOnAddress").unwrap();
        let mut relocations = relocation_arenas(1).unwrap();
        let mut definitions = definition_arenas(1).unwrap();
        let decoded = decode_link_inputs(
            &data_refs.bytes,
            &data_refs.archive_group,
            &data_refs.archive_member,
            &data_refs.import_alias,
            ObjectFormat::Coff,
            &mut relocations,
            &mut definitions,
        )
        .unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.inputs[0].symbol, "__imp_WaitOnAddress");
        assert_eq!(
            decoded.inputs[0].symbol_target,
            LinkDefinitionTarget::PeImportAddress
        );
        assert!(decoded.inputs[0].text.is_empty());
        assert!(matches!(
            decoded.inputs[0].relocations,
            [LinkRelocation {
                target: LinkRelocationTarget::PeImportMetadata {
                    library: "api-ms-win-core-synch-l1-2-0.dll",
                    symbol: "WaitOnAddress",
                },
                ..
            }]
        ));
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
    fn selects_bounded_pe_capacity_tiers_at_exact_boundaries() {
        let cases = [
            (0, PeCapacityTier::Tiny),
            (16 * 1024, PeCapacityTier::Tiny),
            (16 * 1024 + 1, PeCapacityTier::Small),
            (256 * 1024, PeCapacityTier::Small),
            (256 * 1024 + 1, PeCapacityTier::Medium),
            (512 * 1024, PeCapacityTier::Medium),
            (512 * 1024 + 1, PeCapacityTier::Large),
            (768 * 1024, PeCapacityTier::Large),
            (768 * 1024 + 1, PeCapacityTier::Maximum),
            (1024 * 1024, PeCapacityTier::Maximum),
        ];

        for (payload, expected) in cases {
            assert_eq!(pe_capacity_tier(payload), expected);
        }
    }

    #[test]
    fn contextualizes_unresolved_pe_code_targets_by_typed_layout() {
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
            identity: None,
            kind: PeDataKind::Writable,
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
        let defined_contextual =
            contextualize_pe_writable_relocations(&[defined], &writable, &mut defined_arenas)
                .unwrap();
        assert_eq!(
            defined_contextual[0].relocations[0].target,
            LinkRelocationTarget::Symbol("marker")
        );

        let import_definition = [LinkDefinition {
            symbol: "__imp_WaitOnAddress",
            target: LinkDefinitionTarget::PeImportAddress,
        }];
        let import_relocation = [LinkRelocation {
            offset: 2,
            target: LinkRelocationTarget::PeImportAddress {
                library: "api-ms-win-core-synch-l1-2-0.dll",
                symbol: "WaitOnAddress",
            },
            addend: -4,
        }];
        let import = LinkInput {
            symbol: "WaitOnAddress",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &import_definition,
            text: &[0xff, 0x25, 0, 0, 0, 0],
            readonly_data: &[],
            relocations: &import_relocation,
        };
        let alias_relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("__imp_WaitOnAddress"),
            addend: -4,
        }];
        let alias_user = LinkInput {
            relocations: &alias_relocation,
            ..input
        };
        let mut import_arenas = relocation_arenas(2).unwrap();
        let import_contextual =
            contextualize_pe_writable_relocations(&[alias_user, import], &[], &mut import_arenas)
                .unwrap();
        assert_eq!(
            import_contextual[0].relocations[0].target,
            LinkRelocationTarget::PeImportAddress {
                library: "api-ms-win-core-synch-l1-2-0.dll",
                symbol: "WaitOnAddress",
            }
        );

        let data_metadata = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::PeImportMetadata {
                library: "api-ms-win-core-synch-l1-2-0.dll",
                symbol: "DATA",
            },
            addend: 0,
        }];
        let data_import = LinkInput {
            symbol: "__imp_DATA",
            symbol_target: LinkDefinitionTarget::PeImportAddress,
            additional_definitions: &[],
            text: &[],
            readonly_data: &[],
            relocations: &data_metadata,
        };
        let data_alias_relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("__imp_DATA"),
            addend: -4,
        }];
        let data_alias_user = LinkInput {
            relocations: &data_alias_relocation,
            ..input
        };
        let mut data_import_arenas = relocation_arenas(2).unwrap();
        let data_import_contextual = contextualize_pe_writable_relocations(
            &[data_alias_user, data_import],
            &[],
            &mut data_import_arenas,
        )
        .unwrap();
        assert_eq!(
            data_import_contextual[0].relocations[0].target,
            LinkRelocationTarget::PeImportAddress {
                library: "api-ms-win-core-synch-l1-2-0.dll",
                symbol: "DATA",
            }
        );

        let readonly_identity = CoffSectionIdentity::new(14, 3).unwrap();
        let readonly_definition = LinkInput {
            symbol: "__guard_dispatch_icall_fptr",
            symbol_target: LinkDefinitionTarget::CoffSection {
                identity: readonly_identity,
                offset: 8,
            },
            additional_definitions: &[],
            text: &[],
            readonly_data: &[0; 16],
            relocations: &[],
        };
        let guard_relocation = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("__guard_dispatch_icall_fptr"),
            addend: -4,
        }];
        let guard_user = LinkInput {
            relocations: &guard_relocation,
            ..input
        };
        let mut guard_arenas = relocation_arenas(2).unwrap();
        let guard_contextual = contextualize_pe_writable_relocations(
            &[guard_user, readonly_definition],
            &[],
            &mut guard_arenas,
        )
        .unwrap();
        assert_eq!(
            guard_contextual[0].relocations[0].target,
            LinkRelocationTarget::CoffSection {
                identity: readonly_identity,
                offset: 8,
            }
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
        assert!(
            selected_link_inputs(
                &[first, second],
                &[0, 0],
                &[0, 0],
                &[0, 1],
                &strict,
                "entry",
            )
            .is_err()
        );

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
        assert!(
            selected_link_inputs(
                &[first, longer],
                &[0, 0],
                &[0, 0],
                &[0, 1],
                &same_size,
                "entry",
            )
            .is_err()
        );

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
        assert!(
            selected_link_inputs(
                &[first, second],
                &[0, 0],
                &[0, 0],
                &[3, 7],
                &same_size,
                "literal",
            )
            .is_err()
        );
        let exact = [CoffTextComdatSelection::ExactMatch; 2];
        assert!(
            selected_link_inputs(
                &[first, second],
                &[0, 0],
                &[0, 0],
                &[3, 7],
                &exact,
                "literal",
            )
            .is_err()
        );

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
    fn rebinds_readonly_comdat_losers_to_exact_selected_sections() {
        let winner_identity = CoffSectionIdentity::new(3, 7).unwrap();
        let loser_identity = CoffSectionIdentity::new(5, 11).unwrap();
        let winner_definitions = [LinkDefinition {
            symbol: ".text$shared",
            target: LinkDefinitionTarget::CoffTextSection {
                identity: winner_identity,
                offset: 0,
            },
        }];
        let loser_definitions = [LinkDefinition {
            symbol: ".text$shared",
            target: LinkDefinitionTarget::CoffTextSection {
                identity: loser_identity,
                offset: 0,
            },
        }];
        let winner = LinkInput {
            symbol: "shared",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &winner_definitions,
            text: &[0x90, 0x90, 0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let loser = LinkInput {
            additional_definitions: &loser_definitions,
            text: &[0xcc, 0xc3],
            ..winner
        };
        let selected = selected_link_inputs(
            &[winner, loser],
            &[0, 0],
            &[0, 0],
            &[2, 4],
            &[CoffTextComdatSelection::Any; 2],
            "shared",
        )
        .unwrap();
        assert_eq!(selected.inputs.len(), 1);
        assert_eq!(
            &selected.section_rebindings[..],
            &[CoffSectionRebinding {
                discarded: loser_identity,
                selected: winner_identity,
            }]
        );

        let relocation = PeReadonlyAbsoluteRelocation {
            readonly_owner: ".rdata$shared",
            readonly_identity: Some(CoffSectionIdentity::new(5, 13).unwrap()),
            readonly_offset: 8,
            target_symbol: ".text$shared",
            target_identity: Some(loser_identity),
            target_offset: 2,
            addend: -7,
            kind: mrml_rustc::linker::PeReadonlyRelocationKind::Address64,
        };
        let rebound = rebind_selected_readonly_comdat_target(&selected, relocation).unwrap();
        assert_eq!(rebound.target_identity, Some(winner_identity));
        assert_eq!(rebound.target_offset, relocation.target_offset);
        assert_eq!(rebound.addend, relocation.addend);
        assert_eq!(rebound.readonly_identity, relocation.readonly_identity);
        assert_eq!(rebound.kind, relocation.kind);

        let unproven = selected_link_inputs(
            &[winner],
            &[0],
            &[0],
            &[2],
            &[CoffTextComdatSelection::Any],
            "shared",
        )
        .unwrap();
        assert_eq!(
            rebind_selected_readonly_comdat_target(&unproven, relocation)
                .unwrap()
                .target_identity,
            Some(loser_identity)
        );
        assert!(
            rebind_selected_readonly_comdat_target(
                &selected,
                PeReadonlyAbsoluteRelocation {
                    target_offset: winner.text.len() + 1,
                    ..relocation
                },
            )
            .is_err()
        );
    }

    #[test]
    fn retains_exact_text_sections_referenced_by_readonly_relocations() {
        let identity = CoffSectionIdentity::new(9, 25).unwrap();
        let entry = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let target = LinkInput {
            symbol: ".text$local",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let definitions = [LinkDefinition {
            symbol: "callback",
            target: LinkDefinitionTarget::Text(4),
        }];
        let sibling_relocations = [
            LinkRelocation {
                offset: 0,
                target: LinkRelocationTarget::Symbol("late_dependency"),
                addend: -4,
            },
            LinkRelocation {
                offset: 4,
                target: LinkRelocationTarget::RequiredSymbol("late_sibling_dependency"),
                addend: -4,
            },
        ];
        let sibling = LinkInput {
            symbol: "helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &definitions,
            text: &[0; 8],
            readonly_data: &[],
            relocations: &sibling_relocations,
        };
        let transitive_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("transitive_dependency"),
            addend: -4,
        }];
        let dependency = LinkInput {
            symbol: "late_dependency",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0; 4],
            readonly_data: &[],
            relocations: &transitive_relocations,
        };
        let sibling_dependency = LinkInput {
            symbol: "late_sibling_dependency",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let transitive_dependency = LinkInput {
            symbol: "transitive_dependency",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let inputs = [
            entry,
            target,
            sibling,
            dependency,
            sibling_dependency,
            transitive_dependency,
        ];
        let mut selected = selected_link_inputs(
            &inputs,
            &[0, 4, 4, 5, 6, 7],
            &[0, 7, 7, 9, 11, 13],
            &[0, 8, 8, 10, 12, 14],
            &[CoffTextComdatSelection::None; 6],
            "entry",
        )
        .unwrap();
        assert_eq!(selected.inputs.len(), 1);
        let relocation = [PeReadonlyAbsoluteRelocation {
            readonly_owner: "entry",
            readonly_identity: None,
            readonly_offset: 0,
            target_symbol: ".text$local",
            target_identity: Some(identity),
            target_offset: 0,
            addend: 0,
            kind: mrml_rustc::linker::PeReadonlyRelocationKind::Address64,
        }];
        assert!(
            retain_exact_readonly_relocation_targets(
                &inputs,
                &[0, 4, 4, 5, 6, 7],
                &[0, 7, 7, 9, 11, 13],
                &[0, 8, 8, 10, 12, 14],
                &[CoffTextComdatSelection::None; 6],
                &mut selected,
                &relocation,
            )
            .unwrap()
        );
        assert_eq!(selected.inputs.len(), 3);
        assert_eq!(selected.archive_group[1], 4);
        assert_eq!(selected.archive_member[1], 7);
        assert_eq!(selected.source_object[1], 8);
        assert_eq!(selected.inputs[2].additional_definitions, &definitions);
        assert!(
            retain_named_code_targets(
                &inputs,
                &[0, 4, 4, 5, 6, 7],
                &[0, 7, 7, 9, 11, 13],
                &[0, 8, 8, 10, 12, 14],
                &[CoffTextComdatSelection::None; 6],
                &mut selected,
                1,
            )
            .unwrap()
        );
        assert_eq!(selected.inputs.len(), 5);
        assert_eq!(selected.inputs[3].symbol, "late_dependency");
        assert_eq!(selected.inputs[4].symbol, "late_sibling_dependency");
        assert!(
            selected
                .inputs
                .iter()
                .all(|input| input.symbol != "transitive_dependency")
        );
        assert!(
            retain_named_code_targets(
                &inputs,
                &[0, 4, 4, 5, 6, 7],
                &[0, 7, 7, 9, 11, 13],
                &[0, 8, 8, 10, 12, 14],
                &[CoffTextComdatSelection::None; 6],
                &mut selected,
                3,
            )
            .unwrap()
        );
        assert_eq!(selected.inputs.len(), 6);
        assert_eq!(selected.inputs[5].symbol, "transitive_dependency");
        assert!(
            !retain_exact_readonly_relocation_targets(
                &inputs,
                &[0, 4, 4, 5, 6, 7],
                &[0, 7, 7, 9, 11, 13],
                &[0, 8, 8, 10, 12, 14],
                &[CoffTextComdatSelection::None; 6],
                &mut selected,
                &relocation,
            )
            .unwrap()
        );
    }

    #[test]
    fn reports_exact_duplicate_globals_without_colliding_typed_sections() {
        let first_identity = CoffSectionIdentity::new(4, 7).unwrap();
        let second_identity = CoffSectionIdentity::new(5, 9).unwrap();
        let typed_first = LinkInput {
            symbol: ".text$shared",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity: first_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let typed_second = LinkInput {
            symbol: ".text$shared",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity: second_identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        assert_eq!(
            duplicate_global_link_symbol(&[typed_first, typed_second]),
            None
        );

        let first = LinkInput {
            symbol: "entry",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let duplicate = [LinkDefinition {
            symbol: "entry",
            target: LinkDefinitionTarget::Text(0),
        }];
        let second = LinkInput {
            symbol: "helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &duplicate,
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        assert_eq!(
            duplicate_global_link_symbol(&[first, second]),
            Some("entry")
        );
    }

    #[test]
    fn retains_archive_member_siblings_without_comdat_losers() {
        let entry_relocations = [LinkRelocation {
            offset: 0,
            target: LinkRelocationTarget::Symbol("shared"),
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
        let winner_identity = CoffSectionIdentity::new(2, 5).unwrap();
        let winner_definitions = [LinkDefinition {
            symbol: ".text$shared",
            target: LinkDefinitionTarget::CoffTextSection {
                identity: winner_identity,
                offset: 0,
            },
        }];
        let winner = LinkInput {
            symbol: "shared",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &winner_definitions,
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let identity = CoffSectionIdentity::new(3, 11).unwrap();
        let typed_target = LinkInput {
            symbol: ".text$late",
            symbol_target: LinkDefinitionTarget::CoffTextSection {
                identity,
                offset: 0,
            },
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let loser_identity = CoffSectionIdentity::new(3, 13).unwrap();
        let loser_definitions = [LinkDefinition {
            symbol: ".text$shared",
            target: LinkDefinitionTarget::CoffTextSection {
                identity: loser_identity,
                offset: 0,
            },
        }];
        let loser = LinkInput {
            symbol: "shared",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &loser_definitions,
            text: &[0xcc],
            readonly_data: &[],
            relocations: &[],
        };
        let sibling = LinkInput {
            symbol: "late_helper",
            symbol_target: LinkDefinitionTarget::Text(0),
            additional_definitions: &[],
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        let inputs = [entry, winner, typed_target, loser, sibling];
        let groups = [0, 1, 2, 2, 2];
        let members = [0, 7, 9, 9, 9];
        let sources = [0, 1, 3, 3, 3];
        let policies = [
            CoffTextComdatSelection::None,
            CoffTextComdatSelection::Any,
            CoffTextComdatSelection::None,
            CoffTextComdatSelection::Any,
            CoffTextComdatSelection::None,
        ];
        let mut selected =
            selected_link_inputs(&inputs, &groups, &members, &sources, &policies, "entry").unwrap();
        assert_eq!(selected.inputs.len(), 2);
        assert!(
            retain_input_archive_member(
                &inputs,
                &groups,
                &members,
                &sources,
                &policies,
                &mut selected,
                2,
            )
            .unwrap()
        );
        assert_eq!(selected.inputs.len(), 4);
        assert_eq!(
            selected
                .inputs
                .iter()
                .filter(|input| input.symbol == "shared")
                .count(),
            1
        );
        assert!(selected.inputs.iter().any(|input| {
            matches!(
                input.symbol_target,
                LinkDefinitionTarget::CoffTextSection {
                    identity: candidate,
                    ..
                } if candidate == identity
            )
        }));
        assert!(
            selected
                .inputs
                .iter()
                .any(|input| input.symbol == "late_helper")
        );
        assert_eq!(
            &selected.section_rebindings[..],
            &[CoffSectionRebinding {
                discarded: loser_identity,
                selected: winner_identity,
            }]
        );
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

    #[test]
    fn empty_archive_index_does_not_poison_later_index_selection() {
        run_with_linker_stack(empty_archive_index_does_not_poison_later_index_selection_on_stack);
    }

    fn empty_archive_index_does_not_poison_later_index_selection_on_stack() {
        let entry = compile_source_function_with_options::<4096, 4096, 8, 8, 8, 32>(
            "#[unsafe(no_mangle)] pub extern \"C\" fn entry() -> i32 { 42 }",
            "entry",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        let mut empty = Vector::with_capacity(1024).unwrap();
        empty.try_extend_from_slice(b"!<arch>\n").unwrap();
        append_archive_member(&mut empty, "/", &[0; 8]);
        append_archive_member(&mut empty, "unused.o/", b"not an object");

        let mut indexed = Vector::with_capacity(8 * 1024).unwrap();
        indexed.try_extend_from_slice(b"!<arch>\n").unwrap();
        let index = [0, 0, 0, 1, 0, 0, 0, 82, b'e', b'n', b't', b'r', b'y', 0];
        append_archive_member(&mut indexed, "/", &index);
        append_archive_member(&mut indexed, "entry.o/", entry.bytes());

        let archives = [empty, indexed];
        let refs = link_object_refs(&archives, ObjectFormat::Elf64, "entry").unwrap();
        assert_eq!(&refs.bytes[..], &[entry.bytes()]);
        assert_eq!(&refs.archive_group[..], &[2]);
        assert_eq!(&refs.archive_member[..], &[1]);
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
