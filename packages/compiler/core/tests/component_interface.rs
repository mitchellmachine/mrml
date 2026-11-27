#![no_std]

use mrml_rustc::{ObjectFormat, TargetLayout, compile_source_function};

const INTERFACE_GENERATION: u32 = 3;
const DECOMPRESS_OPERATION: u32 = 1;
const REQUEST_BYTES: u64 = 32;
const RESPONSE_BYTES: u64 = 16;

fn upstream_descriptor_identity(
    generation: u32,
    operation: u32,
    request_bytes: u64,
    response_bytes: u64,
) -> u64 {
    if generation != INTERFACE_GENERATION
        || operation != DECOMPRESS_OPERATION
        || request_bytes != REQUEST_BYTES
        || response_bytes != RESPONSE_BYTES
    {
        return 0;
    }
    (u64::from(generation) << 32) | u64::from(operation)
}

#[test]
fn explicit_component_descriptor_has_upstream_and_mrml_object_evidence() {
    assert_eq!(
        upstream_descriptor_identity(3, 1, 32, 16),
        0x0000_0003_0000_0001
    );
    assert_eq!(upstream_descriptor_identity(4, 1, 32, 16), 0);

    // Independently authored scalar projection of the canonical byte header.
    // It is not a claim that the Rust or C ABI is the MRML component ABI.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(generation: u32, operation: u32, request_bytes: u64, response_bytes: u64) -> u64 { if generation != 3 || operation != 1 || request_bytes != 32 || response_bytes != 16 { return 0; } (generation as u64 << 32) | operation as u64 }";
    for format in [ObjectFormat::Coff, ObjectFormat::Elf64] {
        let object = compile_source_function::<2048, 512, 2, 4, 4, 32>(
            source,
            "probe",
            format,
            TargetLayout::X86_64,
        )
        .expect("mrml-rustc compiles the explicit descriptor projection");
        assert!(!object.is_empty());
    }
}

#[test]
fn compound_boolean_expression_compiles_with_public_frontend_capacities() {
    let source = r#"
        #[unsafe(no_mangle)]
        pub extern "C" fn probe() -> i32 {
            if '\t' == '\x09' && '\n' == '\x0A' && '\r' == '\x0D' && ' ' == '\x20' {
                42
            } else {
                0
            }
        }
    "#;
    for format in [ObjectFormat::Coff, ObjectFormat::Elf64] {
        let object = compile_source_function::<4096, 4096, 64, 16, 64, 256>(
            source,
            "probe",
            format,
            TargetLayout::X86_64,
        )
        .expect("public frontend capacities accommodate the compound expression");
        assert!(!object.is_empty());
    }
}

#[test]
fn char_casts_compile_in_constant_and_runtime_paths() {
    for source in [
        r#"#[unsafe(no_mangle)] pub extern "C" fn probe() -> i32 { '*' as i32 }"#,
        r#"#[unsafe(no_mangle)] pub extern "C" fn probe(value: char) -> i8 { value as i8 }"#,
        r#"#[unsafe(no_mangle)] pub extern "C" fn probe(value: char) -> i32 {
            if value as i128 == 0x1f980i128 { 42 } else { 0 }
        }"#,
        r#"#[unsafe(no_mangle)] pub extern "C" fn probe() -> i32 {
            let value = '\u{ff}';
            if (value as i8) < 0i8 { 42 } else { 0 }
        }"#,
        r#"const VALUE: u128 = '\u{1f980}' as u128;
        #[unsafe(no_mangle)] pub extern "C" fn probe() -> i32 {
            if VALUE as u32 == 0x1f980u32 { 42 } else { 0 }
        }"#,
    ] {
        for format in [ObjectFormat::Coff, ObjectFormat::Elf64] {
            let object = compile_source_function::<4096, 1024, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .expect("char-to-integer cast compiles");
            assert!(!object.is_empty());
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn mrml_v1_scalar_facade_has_independently_parsed_native_object_evidence() {
    let source = "#[mrml_abi::export(version = 1)] pub fn identity(value: u64) -> u64 { value }";

    let coff = compile_source_function::<1024, 128, 2, 2, 2, 16>(
        source,
        "identity",
        ObjectFormat::Coff,
        TargetLayout::X86_64,
    )
    .expect("MRML v1 scalar facade emits COFF");
    let coff = coff.bytes();
    assert_eq!(u32_at(coff, 12), 1, "one COFF symbol");
    let coff_text = u32_at(coff, 40) as usize;
    assert_eq!(coff[coff_text], 0x51, "Windows entry saves rcx");
    let coff_symbols = u32_at(coff, 8) as usize;
    assert_eq!(&coff[coff_symbols..coff_symbols + 8], b"identity");
    assert_eq!(
        i16::from_le_bytes(
            coff[coff_symbols + 12..coff_symbols + 14]
                .try_into()
                .unwrap()
        ),
        1,
        "symbol is defined in .text"
    );

    let elf = compile_source_function::<1024, 128, 2, 2, 2, 16>(
        source,
        "identity",
        ObjectFormat::Elf64,
        TargetLayout::X86_64,
    )
    .expect("MRML v1 scalar facade emits ELF");
    let elf = elf.bytes();
    let sections = u64_at(elf, 40) as usize;
    let text_section = sections + 64;
    let elf_text = u64_at(elf, text_section + 24) as usize;
    assert_eq!(elf[elf_text], 0x57, "System V entry saves rdi");
    let symbol_section = sections + 2 * 64;
    let symbols = u64_at(elf, symbol_section + 24) as usize;
    let string_section = sections + 3 * 64;
    let strings = u64_at(elf, string_section + 24) as usize;
    let function_symbol = symbols + 24;
    let name = u32_at(elf, function_symbol) as usize;
    assert_eq!(&elf[strings + name..strings + name + 8], b"identity");
    assert_eq!(
        u16::from_le_bytes(
            elf[function_symbol + 6..function_symbol + 8]
                .try_into()
                .unwrap()
        ),
        1,
        "symbol is defined in .text"
    );
}
