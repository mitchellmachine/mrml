$ErrorActionPreference = "Stop"

$toolchain = "nightly-2026-08-24-x86_64-pc-windows-gnullvm"
$sysroot = (& rustc "+$toolchain" --print sysroot).Trim()
$lld = Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-gnullvm\bin\rust-lld.exe"
$probe = Join-Path ([System.IO.Path]::GetTempPath()) "mrml-public-stateful-rlib-$PID"
New-Item -ItemType Directory -Path $probe | Out-Null
try {
    & rustc "+$toolchain" --edition=2024 --crate-type=rlib -C panic=abort `
        -C embed-bitcode=no -C codegen-units=8 -C opt-level=3 `
        docs/compiler/probes/public_stateful_rlib_library.rs `
        -o (Join-Path $probe "library.rlib")
    if ($LASTEXITCODE -ne 0) { throw "pinned stateful library compilation failed" }
    & rustc "+$toolchain" --edition=2024 --crate-type=lib --emit=obj `
        -C panic=abort -C embed-bitcode=no -C opt-level=3 `
        docs/compiler/probes/public_stateful_rlib_entry.rs `
        -o (Join-Path $probe "entry.obj")
    if ($LASTEXITCODE -ne 0) { throw "pinned stateful entry compilation failed" }

    $mrmlOutput = Join-Path $probe "mrml.exe"
    $lldOutput = Join-Path $probe "rust-lld.exe"
    & .\target\debug\mrml.exe compiler mrml-rustc-experimental link-pe `
        (Join-Path $probe "entry.obj") (Join-Path $probe "library.rlib") `
        --entry start -o $mrmlOutput --release
    if ($LASTEXITCODE -ne 0) { throw "MRML public stateful rlib link failed" }
    & $lld -flavor link /entry:start /subsystem:console /nodefaultlib `
        "/out:$lldOutput" (Join-Path $probe "entry.obj") `
        (Join-Path $probe "library.rlib")
    if ($LASTEXITCODE -ne 0) { throw "pinned rust-lld stateful rlib link failed" }

    $mrmlImage = [System.IO.File]::ReadAllBytes($mrmlOutput)
    $peOffset = [BitConverter]::ToUInt32($mrmlImage, 0x3c)
    $optionalOffset = $peOffset + 24
    $uninitializedBytes = [BitConverter]::ToUInt32($mrmlImage, $optionalOffset + 12)
    if ($uninitializedBytes -ne 1024) {
        throw "MRML PE reports $uninitializedBytes uninitialized bytes instead of 1024"
    }

    $numberOfSections = [BitConverter]::ToUInt16($mrmlImage, $peOffset + 6)
    $optionalHeaderSize = [BitConverter]::ToUInt16($mrmlImage, $peOffset + 20)
    $sectionTable = $peOffset + 24 + $optionalHeaderSize
    $dataVirtualSize = $null
    $dataRawSize = $null
    for ($index = 0; $index -lt $numberOfSections; $index++) {
        $section = $sectionTable + (40 * $index)
        $name = [Text.Encoding]::ASCII.GetString($mrmlImage, $section, 8).TrimEnd([char]0)
        if ($name -eq ".data") {
            $dataVirtualSize = [BitConverter]::ToUInt32($mrmlImage, $section + 8)
            $dataRawSize = [BitConverter]::ToUInt32($mrmlImage, $section + 16)
            break
        }
    }
    if ($null -eq $dataVirtualSize -or $dataVirtualSize -le $dataRawSize) {
        throw "MRML PE .data does not prove loader-backed zero fill (virtual=$dataVirtualSize raw=$dataRawSize)"
    }

    & $mrmlOutput
    $mrmlStatus = $LASTEXITCODE
    & $lldOutput
    $lldStatus = $LASTEXITCODE
    Write-Output "public-stateful-rlib-pe mrml_exit=$mrmlStatus rust_lld_exit=$lldStatus mrml_bytes=$((Get-Item $mrmlOutput).Length) rust_lld_bytes=$((Get-Item $lldOutput).Length) zero_fill_bytes=$uninitializedBytes"
    if ($mrmlStatus -ne 42 -or $lldStatus -ne 42) {
        throw "public stateful rlib outputs did not both return 42"
    }
} finally {
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse }
}
