#![no_std]
#![cfg_attr(not(test), no_main)]

use mrml_error::{Result, anyhow};
use mrml_runtime::{Text, Vector, mrml_println as println};
use mrml_rustc::{
    CodegenOptions, LinkDefinition, LinkInput, LinkRelocation, LinkRelocationTarget,
    MAX_LINK_DEFINITIONS, MAX_LINK_INPUTS, MAX_LINK_RELOCATIONS, MAX_PE_RUNTIME_FUNCTIONS,
    ObjectFormat, PeRuntimeFunction, PeWritableData, PeWritableRelocation, TargetLayout,
    compile_source_function_with_options, decode_unix_archive,
    decode_x86_64_coff_runtime_functions, decode_x86_64_coff_text_fragment,
    decode_x86_64_coff_writable_data, decode_x86_64_elf_with_definitions,
    link_x86_64_elf_executable, link_x86_64_pe_with_data_and_unwind,
    select_ordered_static_link_members, x86_64_coff_text_fragment_count,
};

#[cfg_attr(test, allow(dead_code))]
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_OBJECT_BYTES: usize = 4096;
#[cfg_attr(test, allow(dead_code))]
const MAX_ARCHIVE_BYTES: usize = MAX_OBJECT_BYTES * MAX_LINK_INPUTS;
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

struct DecodedLinkInputs<'data, 'relocations, 'definitions> {
    inputs: Vector<LinkInput<'data, 'relocations, 'definitions>>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
}

struct SelectedLinkInputs<'data, 'relocations, 'definitions> {
    inputs: Vector<LinkInput<'data, 'relocations, 'definitions>>,
    archive_group: Vector<u16>,
    archive_member: Vector<u16>,
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
        let objects = read_link_objects(&arguments[2..arguments.len() - 4])?;
        let object_refs = link_object_refs(&objects)?;
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
        let objects = read_link_objects(&arguments[2..arguments.len() - 4])?;
        let object_refs = link_object_refs(&objects)?;
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

fn read_link_objects(paths: &[Text]) -> Result<Vector<Vector<u8>>> {
    if paths.is_empty() || paths.len() > MAX_LINK_INPUTS {
        return Err(anyhow!("link input count must be between 1 and 256"));
    }
    let mut objects = Vector::with_capacity(paths.len())
        .map_err(|_| anyhow!("could not allocate link input list"))?;
    for path in paths {
        objects
            .try_push(mrml_runtime::read_file_bounded(path, MAX_ARCHIVE_BYTES)?)
            .map_err(|_| anyhow!("could not allocate link input list"))?;
    }
    Ok(objects)
}

fn link_object_refs(objects: &[Vector<u8>]) -> Result<LinkObjectRefs<'_>> {
    let mut refs = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link input reference list"))?;
    let mut archive_group = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link input origin list"))?;
    let mut archive_member = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link member origin list"))?;
    let mut next_archive_group = 1u16;
    for object in objects {
        if object.get(..8) == Some(b"!<arch>\n") {
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            let mut next_archive_member = 1u16;
            for member in archive.members() {
                if member.name == "lib.rmeta" || member.name == "lib.rmeta-link" {
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
                    .try_push(next_archive_member)
                    .map_err(|_| anyhow!("could not allocate link member origin list"))?;
                next_archive_member = next_archive_member
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("archive member identity overflow"))?;
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
    let mut inputs = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
    let mut archive_group = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate decoded link origin list"))?;
    let mut archive_member = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate decoded link member list"))?;
    let mut remaining_arenas = relocation_arenas;
    let mut remaining_definitions = definition_arenas;
    for (object_index, object) in objects.iter().enumerate() {
        let fragment_count = match format {
            ObjectFormat::Coff => {
                x86_64_coff_text_fragment_count(object).map_err(mrml_error::message)?
            }
            ObjectFormat::Elf64 => 1,
        };
        if inputs
            .len()
            .checked_add(fragment_count)
            .unwrap_or(usize::MAX)
            > MAX_LINK_INPUTS
        {
            return Err(anyhow!("expanded link fragment count exceeds 256"));
        }
        for fragment_index in 0..fragment_count {
            let (arena, rest) = remaining_arenas
                .split_first_mut()
                .ok_or_else(|| anyhow!("link relocation arena count mismatch"))?;
            let (definitions, definition_rest) = remaining_definitions
                .split_first_mut()
                .ok_or_else(|| anyhow!("link definition arena count mismatch"))?;
            let input = match format {
                ObjectFormat::Coff => {
                    decode_x86_64_coff_text_fragment(object, fragment_index, arena, definitions)
                }
                ObjectFormat::Elf64 => {
                    decode_x86_64_elf_with_definitions(object, arena, definitions)
                }
            }
            .map_err(mrml_error::message)?;
            inputs
                .try_push(input)
                .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
            archive_group
                .try_push(object_archive_group[object_index])
                .map_err(|_| anyhow!("could not allocate decoded link origin list"))?;
            archive_member
                .try_push(object_archive_member[object_index])
                .map_err(|_| anyhow!("could not allocate decoded link member list"))?;
            remaining_arenas = rest;
            remaining_definitions = definition_rest;
        }
    }
    Ok(DecodedLinkInputs {
        inputs,
        archive_group,
        archive_member,
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
                    text_offset: 0,
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
    for object in objects {
        let object_fragments = match format {
            ObjectFormat::Coff => {
                x86_64_coff_text_fragment_count(object).map_err(mrml_error::message)?
            }
            ObjectFormat::Elf64 => 1,
        };
        count = count
            .checked_add(object_fragments)
            .ok_or_else(|| anyhow!("expanded link fragment count overflow"))?;
        if count > MAX_LINK_INPUTS {
            return Err(anyhow!("expanded link fragment count exceeds 256"));
        }
    }
    Ok(count)
}

fn selected_link_inputs<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_group: &[u16],
    archive_member: &[u16],
    entry: &str,
) -> Result<SelectedLinkInputs<'data, 'relocations, 'definitions>> {
    let selection =
        select_ordered_static_link_members(inputs, archive_group, archive_member, entry)
            .map_err(mrml_error::message)?;
    let mut selected = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link input list"))?;
    let mut selected_group = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link origin list"))?;
    let mut selected_member = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link member list"))?;
    for index in selection.indices() {
        selected
            .try_push(inputs[*index])
            .map_err(|_| anyhow!("could not allocate selected link input list"))?;
        selected_group
            .try_push(archive_group[*index])
            .map_err(|_| anyhow!("could not allocate selected link origin list"))?;
        selected_member
            .try_push(archive_member[*index])
            .map_err(|_| anyhow!("could not allocate selected link member list"))?;
    }
    Ok(SelectedLinkInputs {
        inputs: selected,
        archive_group: selected_group,
        archive_member: selected_member,
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
            .archive_group
            .iter()
            .zip(selected.archive_member.iter())
            .any(|(group, member)| {
                *group == archive_group[object_index] && *member == archive_member[object_index]
            });
        if selected_object {
            for function in decode_x86_64_coff_runtime_functions(objects[object_index], arena)
                .map_err(mrml_error::message)?
            {
                if runtime_functions.len() == MAX_PE_RUNTIME_FUNCTIONS {
                    return Err(anyhow!("selected PE runtime-function count exceeds 256"));
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
                    target_readonly_owner: "unused",
                    target_readonly_offset: 0,
                }; MAX_LINK_RELOCATIONS],
            )
            .map_err(|_| anyhow!("could not allocate writable relocation arenas"))?;
    }
    Ok(arenas)
}

fn selected_writable_data<'data, 'relocations>(
    objects: &[&'data [u8]],
    archive_group: &[u16],
    archive_member: &[u16],
    selected: &SelectedLinkInputs<'data, '_, '_>,
    arenas: &'relocations mut [[PeWritableRelocation<'data>; MAX_LINK_RELOCATIONS]],
) -> Result<Vector<PeWritableData<'data, 'relocations>>> {
    let mut output = Vector::with_capacity(objects.len())
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
        let (arena, rest) = remaining
            .split_first_mut()
            .ok_or_else(|| anyhow!("writable relocation arena count mismatch"))?;
        if let Some(owner) = owner {
            if let Some(data) =
                decode_x86_64_coff_writable_data(objects[object_index], owner, arena)
                    .map_err(mrml_error::message)?
            {
                output
                    .try_push(data)
                    .map_err(|_| anyhow!("could not allocate selected writable data list"))?;
            }
        }
        remaining = rest;
    }
    Ok(output)
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
        entry,
    )?;
    let mut runtime_arena = [PeRuntimeFunction {
        begin_symbol: "unused",
        begin_offset: 0,
        end_symbol: "unused",
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
    let mut writable_arenas = writable_relocation_arenas(objects.len())?;
    let writable_data = selected_writable_data(
        objects,
        archive_group,
        archive_member,
        &selected,
        &mut writable_arenas,
    )?;
    let payload = selected_payload_bound(&selected.inputs, &runtime_functions, &writable_data)?;
    if payload <= 16 * 1024 {
        return write_pe_image::<{ 32 * 1024 }, { 16 * 1024 }>(
            &selected.inputs,
            &runtime_functions,
            &writable_data,
            entry,
            output,
        );
    }
    if payload <= 256 * 1024 {
        return write_pe_image::<{ 512 * 1024 }, { 256 * 1024 }>(
            &selected.inputs,
            &runtime_functions,
            &writable_data,
            entry,
            output,
        );
    }
    write_pe_image::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(
        &selected.inputs,
        &runtime_functions,
        &writable_data,
        entry,
        output,
    )
}

fn write_pe_image<const MAX_IMAGE: usize, const MAX_LINKED: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    runtime_functions: &[PeRuntimeFunction<'_>],
    writable_data: &[PeWritableData<'_, '_>],
    entry: &str,
    output: &str,
) -> Result<()> {
    let executable = link_x86_64_pe_with_data_and_unwind::<MAX_IMAGE, MAX_LINKED>(
        inputs,
        entry,
        runtime_functions,
        writable_data,
    )
    .map_err(mrml_error::message)?;
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
    archive_group: &[u16],
    archive_member: &[u16],
    entry: &str,
    output: &str,
) -> Result<()> {
    let fragment_count = expanded_fragment_count(objects, ObjectFormat::Elf64)?;
    let mut arenas = relocation_arenas(fragment_count)?;
    let mut definitions = definition_arenas(fragment_count)?;
    let decoded = decode_link_inputs(
        objects,
        archive_group,
        archive_member,
        ObjectFormat::Elf64,
        &mut arenas,
        &mut definitions,
    )?;
    let selected = selected_link_inputs(
        &decoded.inputs,
        &decoded.archive_group,
        &decoded.archive_member,
        entry,
    )?;
    let payload = selected_payload_bound(&selected.inputs, &[], &[])?;
    if payload <= 16 * 1024 {
        return write_elf_image::<{ 32 * 1024 }, { 16 * 1024 }>(&selected.inputs, entry, output);
    }
    if payload <= 256 * 1024 {
        return write_elf_image::<{ 512 * 1024 }, { 256 * 1024 }>(&selected.inputs, entry, output);
    }
    write_elf_image::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&selected.inputs, entry, output)
}

fn write_elf_image<const MAX_IMAGE: usize, const MAX_LINKED: usize>(
    inputs: &[LinkInput<'_, '_, '_>],
    entry: &str,
    output: &str,
) -> Result<()> {
    let executable = link_x86_64_elf_executable::<MAX_IMAGE, MAX_LINKED>(inputs, entry)
        .map_err(mrml_error::message)?;
    mrml_runtime::write_file(output, executable.bytes())?;
    println!(
        "linked {} to {} deterministic ELF64 bytes",
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
            .checked_add(data.bytes.len())
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

    fn append_archive_member(archive: &mut Vector<u8>, name: &str, bytes: &[u8]) {
        let mut header = [b' '; 60];
        let name = name.as_bytes();
        header[..name.len()].copy_from_slice(name);
        assert!(bytes.len() < 10);
        header[48] = b'0' + u8::try_from(bytes.len()).unwrap();
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
    fn bounds_selected_payload_with_per_input_alignment_headroom() {
        let inputs = [
            LinkInput {
                symbol: "a",
                additional_definitions: &[],
                text: &[0; 3],
                readonly_data: &[0; 5],
                relocations: &[],
            },
            LinkInput {
                symbol: "b",
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
    fn preserves_archive_and_member_identity_before_fragment_expansion() {
        let mut archive = Vector::with_capacity(256).unwrap();
        for byte in b"!<arch>\n" {
            archive.try_push(*byte).unwrap();
        }
        append_archive_member(&mut archive, "first.o/", b"one");
        append_archive_member(&mut archive, "second.o/", b"two");
        let objects = [archive, Vector::from(*b"explicit")];
        let refs = link_object_refs(&objects).unwrap();
        assert_eq!(&refs.archive_group[..], &[1, 1, 0]);
        assert_eq!(&refs.archive_member[..], &[1, 2, 0]);
    }
}
