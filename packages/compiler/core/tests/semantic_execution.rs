extern crate std;

use mrml_rustc::{
    CodegenErrorKind, CompileErrorKind, ObjectFormat, TargetLayout, compile_source_function,
};
use std::{ffi::c_void, process::Command, sync::Once};

#[cfg(target_os = "windows")]
const FORMAT: ObjectFormat = ObjectFormat::Coff;
#[cfg(not(target_os = "windows"))]
const FORMAT: ObjectFormat = ObjectFormat::Elf64;
#[cfg(target_os = "windows")]
const TOOLCHAIN: &str = "nightly-2026-08-24-x86_64-pc-windows-gnullvm";
#[cfg(not(target_os = "windows"))]
const TOOLCHAIN: &str = "nightly-2026-08-24-x86_64-unknown-linux-gnu";
const COMMIT: &str = "fb6531d550e0075b9eb9a51464f404805eec87d9";
static ORACLE: Once = Once::new();

fn verify_oracle() {
    ORACLE.call_once(|| {
        let output = Command::new("rustup")
            .args(["run", TOOLCHAIN, "rustc", "-Vv"])
            .output()
            .expect("launch pinned rustc");
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(COMMIT));
    });
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[cfg(not(target_os = "windows"))]
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[cfg(target_os = "windows")]
fn text_section(object: &[u8]) -> &[u8] {
    let table = 20 + usize::from(u16_at(object, 16));
    for index in 0..usize::from(u16_at(object, 2)) {
        let h = table + index * 40;
        if object.get(h..h + 5) == Some(b".text") {
            assert_eq!(u16_at(object, h + 32), 0, "probe must be relocation-free");
            let (size, offset) = (
                u32_at(object, h + 16) as usize,
                u32_at(object, h + 20) as usize,
            );
            return &object[offset..offset + size];
        }
    }
    panic!("COFF object has no .text")
}
#[cfg(not(target_os = "windows"))]
fn text_section(object: &[u8]) -> &[u8] {
    let (table, stride) = (u64_at(object, 40) as usize, usize::from(u16_at(object, 58)));
    let names_h = table + usize::from(u16_at(object, 62)) * stride;
    let names =
        &object[u64_at(object, names_h + 24) as usize..][..u64_at(object, names_h + 32) as usize];
    for index in 0..usize::from(u16_at(object, 60)) {
        let h = table + index * stride;
        let name = u32_at(object, h) as usize;
        if names.get(name..name + 6) == Some(b".text\0") {
            assert_eq!(u32_at(object, h + 4), 1, ".text is not PROGBITS");
            assert_ne!(u64_at(object, h + 8) & 4, 0, ".text is not executable");
            let (offset, size) = (
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            );
            return &object[offset..offset + size];
        }
    }
    panic!("ELF object has no .text")
}

struct Executable {
    pointer: *mut u8,
    length: usize,
}
impl Executable {
    fn load(code: &[u8]) -> Self {
        assert!(!code.is_empty());
        let pointer = allocate(code.len());
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), pointer, code.len()) };
        protect(pointer, code.len());
        Self {
            pointer,
            length: code.len(),
        }
    }
}
impl Drop for Executable {
    fn drop(&mut self) {
        release(self.pointer, self.length);
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn VirtualAlloc(a: *mut c_void, n: usize, kind: u32, protection: u32) -> *mut c_void;
    fn VirtualProtect(a: *mut c_void, n: usize, protection: u32, old: *mut u32) -> i32;
    fn VirtualFree(a: *mut c_void, n: usize, kind: u32) -> i32;
}
#[cfg(target_os = "windows")]
fn allocate(n: usize) -> *mut u8 {
    let p = unsafe { VirtualAlloc(std::ptr::null_mut(), n, 0x3000, 4) };
    assert!(!p.is_null());
    p.cast()
}
#[cfg(target_os = "windows")]
fn protect(p: *mut u8, n: usize) {
    let mut old = 0;
    assert_ne!(unsafe { VirtualProtect(p.cast(), n, 0x20, &mut old) }, 0);
}
#[cfg(target_os = "windows")]
fn release(p: *mut u8, _: usize) {
    assert_ne!(unsafe { VirtualFree(p.cast(), 0, 0x8000) }, 0);
}

#[cfg(not(target_os = "windows"))]
unsafe extern "C" {
    fn mmap(
        a: *mut c_void,
        n: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn mprotect(a: *mut c_void, n: usize, protection: i32) -> i32;
    fn munmap(a: *mut c_void, n: usize) -> i32;
}
#[cfg(not(target_os = "windows"))]
fn allocate(n: usize) -> *mut u8 {
    let p = unsafe { mmap(std::ptr::null_mut(), n, 3, 0x22, -1, 0) };
    assert_ne!(p as isize, -1);
    p.cast()
}
#[cfg(not(target_os = "windows"))]
fn protect(p: *mut u8, n: usize) {
    assert_eq!(unsafe { mprotect(p.cast(), n, 5) }, 0);
}
#[cfg(not(target_os = "windows"))]
fn release(p: *mut u8, n: usize) {
    assert_eq!(unsafe { munmap(p.cast(), n) }, 0);
}

fn compile(source: &str) -> Executable {
    verify_oracle();
    let object = compile_source_function::<8192, 4096, 8, 8, 8, 128>(
        source,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap();
    Executable::load(text_section(object.bytes()))
}

#[test]
fn nested_else_if_actions_and_returns_match_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(primary: bool, first: bool, second: bool, input: u32) -> u32 { loop { loop { if primary { let selected: u32 = input + 1; selected + 100; return selected; } else if first { let selected: u32 = input + 2; return selected; } else if second { let selected: u32 = input + 3; return selected; } else { let selected: u32 = input + 4; return selected; } } } }",
    );
    let probe: unsafe extern "C" fn(bool, bool, bool, u32) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for p in [false, true] {
        for a in [false, true] {
            for b in [false, true] {
                let expected = if p {
                    41
                } else if a {
                    42
                } else if b {
                    43
                } else {
                    44
                };
                assert_eq!(unsafe { probe(p, a, b, 40) }, expected);
            }
        }
    }
}

#[test]
fn nested_conditional_continue_and_break_actions_match_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let mut inner: u32 = 0; let mut total: u32 = 0; loop { loop { inner += 1; if inner % 2 == 0 { total += 10; continue; } total += inner; if inner == 5 { break; } } return total; } }",
    );
    let probe: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe() }, 29);
}

#[test]
fn nested_reference_mutations_and_return_origins_match_oracle() {
    let code = compile(
        "fn select(input: &mut u32, primary: bool, alternative: bool) -> &mut u32 { loop { loop { if primary { *input += 3; return input; } else if alternative { *input += 5; return input; } else { *input += 7; return input; } } } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut u32, primary: bool, alternative: bool) -> u32 { let returned: &mut u32 = select(input, primary, alternative); *returned += 11; *returned }",
    );
    let probe: unsafe extern "C" fn(*mut u32, bool, bool) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for p in [false, true] {
        for a in [false, true] {
            let mut actual = 20;
            let expected =
                20 + if p {
                    3
                } else if a {
                    5
                } else {
                    7
                } + 11;
            assert_eq!(
                (unsafe { probe(&mut actual, p, a) }, actual),
                (expected, expected)
            );
        }
    }
}

#[test]
fn nested_branch_initializedness_matches_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, choose: bool) -> u32 { let mut value: u32 = input; 'outer: loop { loop { if choose { value += 1; break 'outer; } else { value += 2; break 'outer; } } } value }",
    );
    let probe: unsafe extern "C" fn(u32, bool) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe(40, true) }, 41);
    assert_eq!(unsafe { probe(40, false) }, 42);
}

#[test]
fn supported_inline_assembly_register_output_executes() {
    let code = compile(
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc r10\", inout(\"r10\") input => output); output }",
    );
    let probe: unsafe extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(code.pointer) };
    for input in [0, 1, 40, u32::MAX as u64] {
        assert_eq!(unsafe { probe(input) }, input + 1);
    }
}

#[test]
fn unsupported_constructs_produce_typed_diagnostics_not_objects() {
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { let value: u64 = 1; } } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { return 1; 2; } } } }",
    ] {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                FORMAT,
                TargetLayout::X86_64
            )
            .is_err()
        );
    }
    let delayed = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, choose: bool) -> u32 { let value: u32; 'outer: loop { loop { if choose { value = input + 1; break 'outer; } else { value = input + 2; break 'outer; } } } value }";
    let error = compile_source_function::<2048, 1024, 4, 4, 4, 64>(
        delayed,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap_err();
    assert!(matches!(
        error.kind,
        CompileErrorKind::Codegen(CodegenErrorKind::ImmutableAssignment)
    ));
    let assembly = "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc rbx\", inout(\"rbx\") input => output); output }";
    let error = compile_source_function::<2048, 1024, 4, 4, 4, 64>(
        assembly,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap_err();
    assert!(
        matches!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::InvalidInlineAssembly)
        ),
        "unexpected diagnostic: {error:?}"
    );
}
