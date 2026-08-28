param(
    [Parameter(Mandatory = $true)][string]$Driver,
    [Parameter(Mandatory = $true)][string]$RustLld,
    [Parameter(Mandatory = $true)][string]$Object,
    [Parameter(Mandatory = $true)][string]$Entry,
    [int]$Warmups = 5,
    [int]$Iterations = 50
)

$ErrorActionPreference = "Stop"
$driverPath = (Resolve-Path -LiteralPath $Driver).Path
$lldPath = (Resolve-Path -LiteralPath $RustLld).Path
$objectPath = (Resolve-Path -LiteralPath $Object).Path
$outputRoot = Join-Path ([IO.Path]::GetTempPath()) ("mrml-link-benchmark-" + [Guid]::NewGuid())
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$mrmlOutput = Join-Path $outputRoot "mrml.exe"
$lldOutput = Join-Path $outputRoot "rust-lld.exe"

function Invoke-MrmlLink {
    Remove-Item -LiteralPath $mrmlOutput -Force -ErrorAction SilentlyContinue
    & $driverPath --link-coff $objectPath --entry $Entry -o $mrmlOutput *> $null
    if ($LASTEXITCODE -ne 0) { throw "MRML linker failed" }
}

function Invoke-RustLldLink {
    Remove-Item -LiteralPath $lldOutput -Force -ErrorAction SilentlyContinue
    & $lldPath -flavor link "/entry:$Entry" /subsystem:console /nodefaultlib /fixed "/out:$lldOutput" $objectPath *> $null
    if ($LASTEXITCODE -ne 0) { throw "rust-lld failed" }
}

try {
    1..$Warmups | ForEach-Object { Invoke-MrmlLink; Invoke-RustLldLink }
    $mrmlTimes = @()
    $lldTimes = @()
    1..$Iterations | ForEach-Object {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Invoke-MrmlLink
        $timer.Stop()
        $mrmlTimes += $timer.Elapsed.TotalMilliseconds

        $timer = [Diagnostics.Stopwatch]::StartNew()
        Invoke-RustLldLink
        $timer.Stop()
        $lldTimes += $timer.Elapsed.TotalMilliseconds
    }

    & $mrmlOutput
    $mrmlExit = $LASTEXITCODE
    & $lldOutput
    $lldExit = $LASTEXITCODE
    if ($mrmlExit -ne $lldExit) { throw "linked executable exit codes differ" }

    $mrmlSorted = $mrmlTimes | Sort-Object
    $lldSorted = $lldTimes | Sort-Object
    $middle = [Math]::Floor(($Iterations - 1) / 2)
    [pscustomobject]@{
        object_bytes = (Get-Item -LiteralPath $objectPath).Length
        iterations = $Iterations
        exit_code = $mrmlExit
        mrml_output_bytes = (Get-Item -LiteralPath $mrmlOutput).Length
        rust_lld_output_bytes = (Get-Item -LiteralPath $lldOutput).Length
        mrml_median_ms = [Math]::Round($mrmlSorted[$middle], 3)
        rust_lld_median_ms = [Math]::Round($lldSorted[$middle], 3)
        mrml_mean_ms = [Math]::Round(($mrmlTimes | Measure-Object -Average).Average, 3)
        rust_lld_mean_ms = [Math]::Round(($lldTimes | Measure-Object -Average).Average, 3)
        mrml_min_ms = [Math]::Round($mrmlSorted[0], 3)
        rust_lld_min_ms = [Math]::Round($lldSorted[0], 3)
    }
} finally {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force -ErrorAction SilentlyContinue
}
