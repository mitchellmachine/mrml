#![no_std]
#![cfg_attr(not(test), no_main)]

use mrml_error::{anyhow, Result};
use mrml_runtime::{mrml_println as println, Text, Vector};
use mrml_rustc::{
    compile_source_function_with_options, decode_unix_archive, decode_x86_64_coff_with_definitions,
    decode_x86_64_elf_with_definitions, link_x86_64_elf_executable, link_x86_64_pe,
    select_static_link_inputs, CodegenOptions, LinkDefinition, LinkInput, LinkRelocation,
    LinkRelocationTarget, ObjectFormat, TargetLayout, MAX_LINK_DEFINITIONS, MAX_LINK_INPUTS,
    MAX_LINK_RELOCATIONS,
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
    archive_member: Vector<bool>,
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
            write_linked_pe(&[object.bytes()], &[false], function, output)?;
        }
        EmitKind::ElfExecutable => {
            write_linked_elf(&[object.bytes()], &[false], function, output)?;
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
    let mut archive_member = Vector::with_capacity(MAX_LINK_INPUTS)
        .map_err(|_| anyhow!("could not allocate link input origin list"))?;
    for object in objects {
        if object.get(..8) == Some(b"!<arch>\n") {
            let archive = decode_unix_archive(object).map_err(mrml_error::message)?;
            for member in archive.members() {
                if refs.len() == MAX_LINK_INPUTS {
                    return Err(anyhow!("expanded link input count exceeds 256"));
                }
                refs.try_push(member.bytes)
                    .map_err(|_| anyhow!("could not allocate link input reference list"))?;
                archive_member
                    .try_push(true)
                    .map_err(|_| anyhow!("could not allocate link input origin list"))?;
            }
        } else {
            refs.try_push(&object[..])
                .map_err(|_| anyhow!("could not allocate link input reference list"))?;
            archive_member
                .try_push(false)
                .map_err(|_| anyhow!("could not allocate link input origin list"))?;
        }
    }
    if refs.is_empty() {
        return Err(anyhow!("link input list contains no object members"));
    }
    Ok(LinkObjectRefs {
        bytes: refs,
        archive_member,
    })
}

fn decode_link_inputs<'data, 'relocations, 'definitions>(
    objects: &[&'data [u8]],
    format: ObjectFormat,
    relocation_arenas: &'relocations mut [[LinkRelocation<'data>; MAX_LINK_RELOCATIONS]],
    definition_arenas: &'definitions mut [[LinkDefinition<'data>; MAX_LINK_DEFINITIONS]],
) -> Result<Vector<LinkInput<'data, 'relocations, 'definitions>>> {
    let mut inputs = Vector::with_capacity(objects.len())
        .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
    let mut remaining_arenas = relocation_arenas;
    let mut remaining_definitions = definition_arenas;
    for object in objects {
        let (arena, rest) = remaining_arenas
            .split_first_mut()
            .ok_or_else(|| anyhow!("link relocation arena count mismatch"))?;
        let (definitions, definition_rest) = remaining_definitions
            .split_first_mut()
            .ok_or_else(|| anyhow!("link definition arena count mismatch"))?;
        let input = match format {
            ObjectFormat::Coff => decode_x86_64_coff_with_definitions(object, arena, definitions),
            ObjectFormat::Elf64 => decode_x86_64_elf_with_definitions(object, arena, definitions),
        }
        .map_err(mrml_error::message)?;
        inputs
            .try_push(input)
            .map_err(|_| anyhow!("could not allocate decoded link input list"))?;
        remaining_arenas = rest;
        remaining_definitions = definition_rest;
    }
    Ok(inputs)
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

fn selected_link_inputs<'data, 'relocations, 'definitions>(
    inputs: &[LinkInput<'data, 'relocations, 'definitions>],
    archive_member: &[bool],
    entry: &str,
) -> Result<Vector<LinkInput<'data, 'relocations, 'definitions>>> {
    let selection =
        select_static_link_inputs(inputs, archive_member, entry).map_err(mrml_error::message)?;
    let mut selected = Vector::with_capacity(selection.indices().len())
        .map_err(|_| anyhow!("could not allocate selected link input list"))?;
    for index in selection.indices() {
        selected
            .try_push(inputs[*index])
            .map_err(|_| anyhow!("could not allocate selected link input list"))?;
    }
    Ok(selected)
}

fn write_linked_pe(
    objects: &[&[u8]],
    archive_member: &[bool],
    entry: &str,
    output: &str,
) -> Result<()> {
    let mut arenas = relocation_arenas(objects.len())?;
    let mut definitions = definition_arenas(objects.len())?;
    let inputs = decode_link_inputs(objects, ObjectFormat::Coff, &mut arenas, &mut definitions)?;
    let selected = selected_link_inputs(&inputs, archive_member, entry)?;
    let executable = link_x86_64_pe::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&selected, entry)
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
    archive_member: &[bool],
    entry: &str,
    output: &str,
) -> Result<()> {
    let mut arenas = relocation_arenas(objects.len())?;
    let mut definitions = definition_arenas(objects.len())?;
    let inputs = decode_link_inputs(objects, ObjectFormat::Elf64, &mut arenas, &mut definitions)?;
    let selected = selected_link_inputs(&inputs, archive_member, entry)?;
    let executable =
        link_x86_64_elf_executable::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&selected, entry)
            .map_err(mrml_error::message)?;
    mrml_runtime::write_file(output, executable.bytes())?;
    println!(
        "linked {} to {} deterministic ELF64 bytes",
        entry,
        executable.bytes().len()
    );
    Ok(())
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
}
