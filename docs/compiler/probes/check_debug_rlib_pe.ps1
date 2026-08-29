$ErrorActionPreference = "Stop"

$toolchain = "nightly-2026-08-24-x86_64-pc-windows-gnullvm"
$sysroot = (& rustc "+$toolchain" --print sysroot).Trim()
$lld = Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-gnullvm\bin\rust-lld.exe"
$probe = Join-Path ([System.IO.Path]::GetTempPath()) "mrml-debug-rlib-$PID"
New-Item -ItemType Directory -Path $probe | Out-Null
try {
    $entry = Join-Path $probe "entry.rlib"
    $dependency = Join-Path $probe "dependency.rlib"
    & rustc "+$toolchain" --edition=2024 --crate-type=rlib -C panic=abort `
        -C embed-bitcode=no -C debuginfo=2 -C opt-level=3 `
        docs/compiler/probes/debug_rlib_entry.rs -o $entry
    if ($LASTEXITCODE -ne 0) { throw "pinned debug entry compilation failed" }
    & rustc "+$toolchain" --edition=2024 --crate-type=rlib -C panic=abort `
        -C embed-bitcode=no -C opt-level=3 `
        docs/compiler/probes/debug_rlib_dependency.rs -o $dependency
    if ($LASTEXITCODE -ne 0) { throw "pinned dependency compilation failed" }

    $mrmlOutput = Join-Path $probe "mrml.exe"
    $lldOutput = Join-Path $probe "rust-lld.exe"
    $driver = Resolve-Path ".\target\mrml-native\windows\release\mrml-rustc.exe"
    & $driver --link-coff $entry $dependency --entry entry -o $mrmlOutput
    if ($LASTEXITCODE -ne 0) { throw "MRML debug rlib link failed" }
    & $lld -flavor link /entry:entry /subsystem:console /nodefaultlib `
        "/out:$lldOutput" $entry $dependency
    if ($LASTEXITCODE -ne 0) { throw "pinned rust-lld debug rlib link failed" }

    & $mrmlOutput
    $mrmlStatus = $LASTEXITCODE
    & $lldOutput
    $lldStatus = $LASTEXITCODE
    Write-Output "debug-rlib-pe mrml_exit=$mrmlStatus rust_lld_exit=$lldStatus mrml_bytes=$((Get-Item $mrmlOutput).Length) rust_lld_bytes=$((Get-Item $lldOutput).Length)"
    if ($mrmlStatus -ne 42 -or $lldStatus -ne 42) {
        throw "debug rlib outputs did not both return 42"
    }

    function Measure-Link($name, $output, [scriptblock]$link) {
        $samples = @()
        for ($iteration = 0; $iteration -lt 55; $iteration++) {
            if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output }
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            & $link
            $timer.Stop()
            if ($LASTEXITCODE -ne 0) { throw "$name benchmark link failed" }
            if ($iteration -ge 5) { $samples += $timer.Elapsed.TotalMilliseconds }
        }
        $ordered = $samples | Sort-Object
        $median = ($ordered[24] + $ordered[25]) / 2
        $mean = ($samples | Measure-Object -Average).Average
        Write-Output ("debug-rlib-pe-benchmark linker={0} median_ms={1:N3} mean_ms={2:N3} iterations=50 warmups=5" -f $name, $median, $mean)
    }
    $mrmlBenchmark = Join-Path $probe "mrml-benchmark.exe"
    $lldBenchmark = Join-Path $probe "rust-lld-benchmark.exe"
    Measure-Link "mrml" $mrmlBenchmark {
        & $driver --link-coff $entry $dependency --entry entry `
            -o $mrmlBenchmark *> $null
    }
    Measure-Link "rust-lld" $lldBenchmark {
        & $lld -flavor link /entry:entry /subsystem:console /nodefaultlib `
            "/out:$lldBenchmark" $entry $dependency *> $null
    }
} finally {
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse }
}
