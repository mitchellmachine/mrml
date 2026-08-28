#![no_std]
#![cfg_attr(not(test), no_main)]

use mrml_error::{Result, anyhow};
use mrml_runtime::mrml_println as println;
use mrml_rustc::{
    CodegenOptions, LinkRelocation, LinkRelocationTarget, MAX_LINK_RELOCATIONS, ObjectFormat,
    TargetLayout, compile_source_function_with_options, decode_x86_64_coff, decode_x86_64_elf,
    link_x86_64_elf_executable, link_x86_64_pe,
};

#[cfg_attr(test, allow(dead_code))]
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_OBJECT_BYTES: usize = 4096;
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
const MAX_LINKED_BYTES: usize = 16 * 1024;
#[cfg_attr(test, allow(dead_code))]
const MAX_EXECUTABLE_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmitKind {
    Object(ObjectFormat),
    Pe,
    ElfExecutable,
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
    if arguments.len() == 7
        && arguments[1] == "--link-coff"
        && arguments[3] == "--entry"
        && arguments[5] == "-o"
    {
        let output = &arguments[6];
        if mrml_runtime::path_exists(output) {
            return Err(anyhow!("refusing to overwrite compiler output"));
        }
        let object = mrml_runtime::read_file_bounded(&arguments[2], MAX_OBJECT_BYTES)?;
        return write_linked_pe(&object, &arguments[4], output);
    }
    if arguments.len() == 7
        && arguments[1] == "--link-elf"
        && arguments[3] == "--entry"
        && arguments[5] == "-o"
    {
        let output = &arguments[6];
        if mrml_runtime::path_exists(output) {
            return Err(anyhow!("refusing to overwrite compiler output"));
        }
        let object = mrml_runtime::read_file_bounded(&arguments[2], MAX_OBJECT_BYTES)?;
        return write_linked_elf(&object, &arguments[4], output);
    }
    if arguments.len() < 8 || arguments[1] != "--emit" || arguments[3] != "--function" {
        return Err(anyhow!(
            "usage: mrml-rustc --emit elf64|coff|pe|elf-executable --function NAME [-C overflow-checks=yes|no] INPUT -o OUTPUT; or mrml-rustc --link-coff|--link-elf INPUT --entry NAME -o OUTPUT"
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
                "usage: mrml-rustc --emit elf64|coff|pe|elf-executable --function NAME [-C overflow-checks=yes|no] INPUT -o OUTPUT; or mrml-rustc --link-coff|--link-elf INPUT --entry NAME -o OUTPUT"
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
            write_linked_pe(object.bytes(), function, output)?;
        }
        EmitKind::ElfExecutable => {
            write_linked_elf(object.bytes(), function, output)?;
        }
    }
    Ok(())
}

fn write_linked_pe(object: &[u8], entry: &str, output: &str) -> Result<()> {
    let mut relocations = [LinkRelocation {
        offset: 0,
        target: LinkRelocationTarget::Symbol("unused"),
        addend: 0,
    }; MAX_LINK_RELOCATIONS];
    let input = decode_x86_64_coff(object, &mut relocations).map_err(mrml_error::message)?;
    let executable = link_x86_64_pe::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&[input], entry)
        .map_err(mrml_error::message)?;
    mrml_runtime::write_file(output, executable.bytes())?;
    println!(
        "linked {} to {} deterministic PE bytes",
        entry,
        executable.bytes().len()
    );
    Ok(())
}

fn write_linked_elf(object: &[u8], entry: &str, output: &str) -> Result<()> {
    let mut relocations = [LinkRelocation {
        offset: 0,
        target: LinkRelocationTarget::Symbol("unused"),
        addend: 0,
    }; MAX_LINK_RELOCATIONS];
    let input = decode_x86_64_elf(object, &mut relocations).map_err(mrml_error::message)?;
    let executable =
        link_x86_64_elf_executable::<MAX_EXECUTABLE_BYTES, MAX_LINKED_BYTES>(&[input], entry)
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
