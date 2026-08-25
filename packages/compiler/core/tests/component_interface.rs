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
