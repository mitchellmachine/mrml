$ErrorActionPreference = "Stop"

$toolchain = "nightly-2026-08-24-x86_64-pc-windows-gnullvm"
$sysroot = (& rustc "+$toolchain" --print sysroot).Trim()
$lld = Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-gnullvm\bin\rust-lld.exe"
$probe = Join-Path ([System.IO.Path]::GetTempPath()) "mrml-public-rlib-$PID"
New-Item -ItemType Directory -Path $probe | Out-Null
try {
    & rustc "+$toolchain" --edition=2024 --crate-type=rlib -C panic=abort `
        -C embed-bitcode=no -C codegen-units=8 -C opt-level=3 `
        docs/compiler/probes/public_rlib_library.rs `
        -o (Join-Path $probe "library.rlib")
    if ($LASTEXITCODE -ne 0) { throw "pinned library compilation failed" }
    & rustc "+$toolchain" --edition=2024 --crate-type=lib --emit=obj `
        -C panic=abort -C embed-bitcode=no -C opt-level=3 `
        docs/compiler/probes/public_rlib_entry.rs `
        -o (Join-Path $probe "entry.obj")
    if ($LASTEXITCODE -ne 0) { throw "pinned entry compilation failed" }

    $mrmlOutput = Join-Path $probe "mrml.exe"
    $lldOutput = Join-Path $probe "rust-lld.exe"
    & .\target\debug\mrml.exe compiler mrml-rustc-experimental link-pe `
        (Join-Path $probe "entry.obj") (Join-Path $probe "library.rlib") `
        --entry start -o $mrmlOutput --release
    if ($LASTEXITCODE -ne 0) { throw "MRML public rlib link failed" }
    & $lld -flavor link /entry:start /subsystem:console /nodefaultlib `
        "/out:$lldOutput" (Join-Path $probe "entry.obj") `
        (Join-Path $probe "library.rlib")
    if ($LASTEXITCODE -ne 0) { throw "pinned rust-lld rlib link failed" }

    & $mrmlOutput
    $mrmlStatus = $LASTEXITCODE
    & $lldOutput
    $lldStatus = $LASTEXITCODE
    $mrmlBytes = (Get-Item -LiteralPath $mrmlOutput).Length
    $lldBytes = (Get-Item -LiteralPath $lldOutput).Length
    Write-Output "public-rlib-pe mrml_exit=$mrmlStatus rust_lld_exit=$lldStatus mrml_bytes=$mrmlBytes rust_lld_bytes=$lldBytes"
    if ($mrmlStatus -ne 42 -or $lldStatus -ne 42) {
        throw "public rlib outputs did not both return 42"
    }

    $driver = Resolve-Path ".\target\mrml-native\windows\release\mrml-rustc.exe"
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
        Write-Output ("public-rlib-pe-benchmark linker={0} median_ms={1:N3} mean_ms={2:N3} iterations=50 warmups=5" -f $name, $median, $mean)
    }
    $mrmlBenchmark = Join-Path $probe "mrml-benchmark.exe"
    $lldBenchmark = Join-Path $probe "rust-lld-benchmark.exe"
    Measure-Link "mrml" $mrmlBenchmark {
        & $driver --link-coff (Join-Path $probe "entry.obj") `
            (Join-Path $probe "library.rlib") --entry start `
            -o $mrmlBenchmark *> $null
    }
    Measure-Link "rust-lld" $lldBenchmark {
        & $lld -flavor link /entry:start /subsystem:console /nodefaultlib `
            "/out:$lldBenchmark" (Join-Path $probe "entry.obj") `
            (Join-Path $probe "library.rlib") *> $null
    }
} finally {
    if (Test-Path -LiteralPath $probe) {
        Remove-Item -LiteralPath $probe -Recurse
    }
}
