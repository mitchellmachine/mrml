$ErrorActionPreference = "Stop"

$toolchain = "nightly-2026-08-29-x86_64-pc-windows-gnullvm"
$sysroot = (& rustc "+$toolchain" --print sysroot).Trim()
if ($LASTEXITCODE -ne 0) { throw "pinned rustc sysroot lookup failed" }
$core = Get-ChildItem `
    (Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-gnullvm\lib\libcore-*.rlib") |
    Select-Object -First 1
if ($null -eq $core) { throw "pinned libcore archive was not found" }
$driver = Resolve-Path ".\target\mrml-native\windows\release\mrml-rustc.exe"
$probe = Join-Path ([System.IO.Path]::GetTempPath()) "mrml-pinned-core-inventory-$PID"
New-Item -ItemType Directory -Path $probe | Out-Null
try {
    $object = Join-Path $probe "consumer.obj"
    & rustc "+$toolchain" --edition=2024 --crate-type=lib --emit=obj `
        -C panic=abort -C embed-bitcode=no -C opt-level=3 `
        docs/compiler/probes/windows_core_consumer.rs -o $object
    if ($LASTEXITCODE -ne 0) { throw "pinned core consumer compilation failed" }

    $output = Join-Path $probe "consumer.exe"
    $diagnostic = (& $driver --link-coff $object $core.FullName `
        --entry entry -o $output 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0) {
        throw "pinned core probe unexpectedly linked; update this recovery probe"
    }
    $expected = "expanded link fragment count exceeds 256"
    if ($diagnostic -notmatch [regex]::Escape($expected)) {
        throw "pinned core probe did not reach the expected content boundary: $diagnostic"
    }
    Write-Output "pinned-core-coff-inventory archive=$($core.Name) result=EXPECTED_FRAGMENT_BOUNDARY"
} finally {
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse }
}
