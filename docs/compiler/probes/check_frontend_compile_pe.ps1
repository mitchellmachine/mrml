$ErrorActionPreference = "Stop"

$probe = Join-Path ([System.IO.Path]::GetTempPath()) "mrml-frontend-compile-pe-$PID.exe"
try {
    & .\target\debug\mrml.exe compiler mrml-rustc-experimental compile-pe `
        docs/compiler/probes/frontend_compile_pe.rs --function start `
        -o $probe --release
    if ($LASTEXITCODE -ne 0) {
        throw "experimental compile-pe frontend failed with exit $LASTEXITCODE"
    }
    & $probe
    $status = $LASTEXITCODE
    $bytes = (Get-Item -LiteralPath $probe).Length
    Write-Output "frontend-compile-pe exit=$status bytes=$bytes"
    if ($status -ne 42) {
        throw "experimental compile-pe output returned $status instead of 42"
    }
} finally {
    if (Test-Path -LiteralPath $probe) {
        Remove-Item -LiteralPath $probe
    }
}
