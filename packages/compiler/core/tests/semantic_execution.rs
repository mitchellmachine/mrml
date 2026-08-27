extern crate std;

use mrml_rustc::{
    CodegenErrorKind, CompileErrorKind, ObjectFormat, TargetLayout, compile_source_function,
};
use std::{ffi::c_void, process::Command, sync::Once, vec::Vec};

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
#[cfg(target_os = "windows")]
fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[cfg(not(target_os = "windows"))]
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
#[cfg(not(target_os = "windows"))]
fn i64_at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

struct ObjectImage {
    code: Vec<u8>,
    data: Vec<u8>,
    relocations: Vec<(usize, usize)>,
}

#[cfg(target_os = "windows")]
fn object_image(object: &[u8]) -> ObjectImage {
    let table = 20 + usize::from(u16_at(object, 16));
    let mut text = None;
    let mut data = None;
    for index in 0..usize::from(u16_at(object, 2)) {
        let h = table + index * 40;
        if object.get(h..h + 5) == Some(b".text") {
            text = Some((
                u32_at(object, h + 20) as usize,
                u32_at(object, h + 16) as usize,
                u32_at(object, h + 24) as usize,
                usize::from(u16_at(object, h + 32)),
            ));
        } else if object.get(h..h + 7) == Some(b".rdata\0") {
            data = Some((
                u32_at(object, h + 20) as usize,
                u32_at(object, h + 16) as usize,
            ));
        }
    }
    let (text_offset, text_size, relocation_offset, relocation_count) =
        text.expect("COFF object has no .text");
    let mut code = object[text_offset..text_offset + text_size].to_vec();
    let data = data.map_or_else(Vec::new, |(offset, size)| {
        object[offset..offset + size].to_vec()
    });
    let mut relocations = Vec::new();
    for index in 0..relocation_count {
        let offset = relocation_offset + index * 10;
        let patch = u32_at(object, offset) as usize;
        assert_eq!(u32_at(object, offset + 4), 1, "unexpected COFF symbol");
        assert_eq!(u16_at(object, offset + 8), 4, "unexpected COFF relocation");
        let addend = i32_at(&code, patch);
        assert!(addend >= 0, "negative COFF read-only addend");
        relocations.push((patch, addend as usize));
        code[patch..patch + 4].fill(0);
    }
    ObjectImage {
        code,
        data,
        relocations,
    }
}
#[cfg(not(target_os = "windows"))]
fn object_image(object: &[u8]) -> ObjectImage {
    let (table, stride) = (u64_at(object, 40) as usize, usize::from(u16_at(object, 58)));
    let names_h = table + usize::from(u16_at(object, 62)) * stride;
    let names =
        &object[u64_at(object, names_h + 24) as usize..][..u64_at(object, names_h + 32) as usize];
    let mut text = None;
    let mut data = None;
    let mut relocation_section = None;
    for index in 0..usize::from(u16_at(object, 60)) {
        let h = table + index * stride;
        let name = u32_at(object, h) as usize;
        if names.get(name..name + 6) == Some(b".text\0") {
            assert_eq!(u32_at(object, h + 4), 1, ".text is not PROGBITS");
            assert_ne!(u64_at(object, h + 8) & 4, 0, ".text is not executable");
            text = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        } else if names.get(name..name + 8) == Some(b".rodata\0") {
            assert_eq!(u32_at(object, h + 4), 1, ".rodata is not PROGBITS");
            data = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        } else if names.get(name..name + 11) == Some(b".rela.text\0") {
            assert_eq!(u32_at(object, h + 4), 4, ".rela.text is not RELA");
            relocation_section = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        }
    }
    let (text_offset, text_size) = text.expect("ELF object has no .text");
    let mut code = object[text_offset..text_offset + text_size].to_vec();
    let data = data.map_or_else(Vec::new, |(offset, size)| {
        object[offset..offset + size].to_vec()
    });
    let mut relocations = Vec::new();
    if let Some((offset, size)) = relocation_section {
        assert_eq!(size % 24, 0, "invalid ELF RELA size");
        for index in 0..size / 24 {
            let relocation = offset + index * 24;
            let patch = u64_at(object, relocation) as usize;
            assert_eq!(u64_at(object, relocation + 8), (1u64 << 32) | 2);
            let addend = i64_at(object, relocation + 16)
                .checked_add(4)
                .expect("ELF addend overflow");
            assert!(addend >= 0, "negative ELF read-only addend");
            relocations.push((patch, addend as usize));
            code[patch..patch + 4].fill(0);
        }
    }
    ObjectImage {
        code,
        data,
        relocations,
    }
}

struct Executable {
    pointer: *mut u8,
    length: usize,
}
impl Executable {
    fn load(image: ObjectImage) -> Self {
        assert!(!image.code.is_empty());
        let data_offset = image.code.len().checked_add(15).unwrap() & !15;
        let length = data_offset.checked_add(image.data.len()).unwrap();
        let pointer = allocate(length);
        unsafe {
            std::ptr::copy_nonoverlapping(image.code.as_ptr(), pointer, image.code.len());
            std::ptr::copy_nonoverlapping(
                image.data.as_ptr(),
                pointer.add(data_offset),
                image.data.len(),
            );
        }
        for (patch, data_addend) in image.relocations {
            assert!(
                patch
                    .checked_add(4)
                    .is_some_and(|end| end <= image.code.len())
            );
            assert!(data_addend <= image.data.len());
            let target = unsafe { pointer.add(data_offset + data_addend) } as isize;
            let next = unsafe { pointer.add(patch + 4) } as isize;
            let displacement = i32::try_from(target - next).expect("relocation out of range");
            unsafe {
                pointer
                    .add(patch)
                    .cast::<i32>()
                    .write_unaligned(displacement)
            };
        }
        protect(pointer, length);
        Self { pointer, length }
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
    fn SetErrorMode(mode: u32) -> u32;
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
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
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
    Executable::load(object_image(object.bytes()))
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
fn subslice_then_index_reference_mutation_executes() {
    for code in [
        compile(
            "fn select(input: &mut [u32; 4], start: usize, index: usize) -> &mut u32 { &mut input[start..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, start, index); *selected += 7; *selected }",
        ),
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
        ),
    ] {
        let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (start, index, target) in [(0, 2, 2), (1, 0, 1), (2, 1, 3)] {
            let mut values = [10, 20, 30, 40];
            let expected = values[target] + 7;
            assert_eq!(unsafe { probe(&mut values, start, index) }, expected);
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40][position]);
                }
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, index, target) in [(0, 2, 2), (1, 0, 1), (2, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 7;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), start, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), start, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 9; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 3, 2, 2), (1, 4, 0, 1), (2, 4, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 9;
        assert_eq!(unsafe { probe(&mut values, start, end, index) }, expected);
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 9; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 3, 2, 2), (1, 4, 0, 1), (2, 4, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 9;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), start, end, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), start, end, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }
}

#[test]
fn subslice_then_index_bounds_report_isolated_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_SUBSLICE_INDEX_TRAP_CHILD";
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        for (start, index) in [(5, 0), (1, 3)] {
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let mut values = [10, 20, 30, 40];
                let _ = unsafe { probe(&mut values, start, index) };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { waitpid(pid, &mut status, 0) },
                pid,
                "waitpid failed"
            );
            assert_eq!(
                status & 0x7f,
                4,
                "unexpected Unix wait status for ({start}, {index}): {status:#x}"
            );
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (start, index) = if case == "range" { (5, 0) } else { (1, 3) };
        let mut values = [10, 20, 30, 40];
        let _ = unsafe { probe(&mut values, start, index) };
        panic!("nested bounds trap unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["range", "index"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "subslice_then_index_bounds_report_isolated_traps",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated nested-bounds probe");
        assert_eq!(
            output.status.code(),
            Some(101),
            "unexpected Windows {case} test status: {}",
            output.status
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
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
fn checked_overflow_reports_an_isolated_trap_exit() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_OVERFLOW_CHILD";
    let code =
        compile("#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { input + 1 }");
    let probe: unsafe extern "C" fn(u32) -> u32 = unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { probe(u32::MAX) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { waitpid(pid, &mut status, 0) },
            pid,
            "waitpid failed"
        );
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { probe(u32::MAX) };
        panic!("checked overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "checked_overflow_reports_an_isolated_trap_exit",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated semantic trap probe");
    #[cfg(target_os = "windows")]
    let status = output.status;
    #[cfg(target_os = "windows")]
    assert!(
        !status.success(),
        "generated overflow trap unexpectedly returned"
    );
    #[cfg(target_os = "windows")]
    {
        assert_eq!(
            status.code(),
            Some(101),
            "unexpected Windows test status: {status}"
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn c_string_byte_view_lengths_and_emptiness_execute() {
    let lengths = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(with_nul: bool) -> usize { if with_nul { c\"hello\".to_bytes_with_nul().len() } else { c\"hello\".to_bytes().len() } }",
    );
    let probe: unsafe extern "C" fn(bool) -> usize =
        unsafe { std::mem::transmute(lengths.pointer) };
    assert_eq!(unsafe { probe(false) }, 5);
    assert_eq!(unsafe { probe(true) }, 6);

    let empty = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(with_nul: bool) -> bool { if with_nul { c\"\".to_bytes_with_nul().is_empty() } else { c\"\".to_bytes().is_empty() } }",
    );
    let probe: unsafe extern "C" fn(bool) -> bool = unsafe { std::mem::transmute(empty.pointer) };
    assert!(unsafe { probe(false) });
    assert!(!unsafe { probe(true) });
}

#[test]
fn relocated_c_string_byte_views_execute_with_exact_contents() {
    let code = compile(
        r####"#[unsafe(no_mangle)] pub extern "C" fn probe(raw: bool) -> &'static [u8] { if raw { cr##"raw\n"#text"##.to_bytes_with_nul() } else { c"hello\n".to_bytes() } }"####,
    );
    let probe: unsafe extern "C" fn(bool) -> &'static [u8] =
        unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe(false) }, b"hello\n");
    assert_eq!(unsafe { probe(true) }, b"raw\\n\"#text\0");
}

#[test]
fn unsupported_constructs_produce_typed_diagnostics_not_objects() {
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { let value: u64 = 1; } } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { return 1; 2; } } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index..][0]; *selected }",
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
