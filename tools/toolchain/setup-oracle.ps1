[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$ToolchainFile = Join-Path $RepoRoot "rust-toolchain.toml"
$ToolchainText = Get-Content -Raw -LiteralPath $ToolchainFile

$ChannelMatch = [regex]::Match($ToolchainText, '(?m)^\s*channel\s*=\s*"([^"]+)"\s*$')
if (-not $ChannelMatch.Success) { throw "Could not read the pinned channel from rust-toolchain.toml" }
$Channel = $ChannelMatch.Groups[1].Value
$WindowsToolchain = "$Channel-x86_64-pc-windows-gnullvm"

function Get-TomlArray([string]$Name) {
    $Match = [regex]::Match($ToolchainText, "(?m)^\s*$Name\s*=\s*\[([^\]]*)\]\s*$")
    if (-not $Match.Success) { return @() }
    return @([regex]::Matches($Match.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { throw "rustup is required" }
$Installed = @(rustup toolchain list)
if (-not ($Installed | Where-Object { $_ -match "^$([regex]::Escape($WindowsToolchain))(\s|$)" })) {
    rustup toolchain install $WindowsToolchain --profile minimal --component rust-mingw
}

$InstalledComponents = @(rustup component list --toolchain $WindowsToolchain --installed)
foreach ($Component in (Get-TomlArray "components")) {
    if (-not ($InstalledComponents | Where-Object { $_ -match "^$([regex]::Escape($Component))(-|$)" })) {
        rustup component add --toolchain $WindowsToolchain $Component
    }
}
if (-not ($InstalledComponents | Where-Object { $_ -match '^rust-mingw(-|$)' })) {
    rustup component add --toolchain $WindowsToolchain rust-mingw
}
$InstalledTargets = @(rustup target list --toolchain $WindowsToolchain --installed)
foreach ($Target in (Get-TomlArray "targets")) {
    if ($InstalledTargets -notcontains $Target) {
        rustup target add --toolchain $WindowsToolchain $Target
    }
}

$OracleFile = Get-ChildItem -LiteralPath (Join-Path $RepoRoot "docs\compiler\oracles") -Filter "ORACLE-*.md" |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $OracleFile) { throw "No oracle record found" }
$OracleText = Get-Content -Raw -LiteralPath $OracleFile.FullName
$CommitMatch = [regex]::Match($OracleText, '(?m)^- full commit: `([0-9a-f]+)`$')
if (-not $CommitMatch.Success) { throw "Could not read the full commit from $($OracleFile.Name)" }
$ExpectedCommit = $CommitMatch.Groups[1].Value
$ActualCommitLine = rustup run $WindowsToolchain rustc -Vv | Where-Object { $_ -like "commit-hash:*" }
$ActualCommit = ($ActualCommitLine -replace '^commit-hash:\s*', '').Trim()
if ($ActualCommit -ne $ExpectedCommit) {
    throw "rustc commit $ActualCommit does not match $($OracleFile.Name) ($ExpectedCommit)"
}

$env:RUSTUP_TOOLCHAIN = $WindowsToolchain
$CargoBin = Join-Path $HOME ".cargo\bin"
if (($env:PATH -split ';') -notcontains $CargoBin) { $env:PATH = "$CargoBin;$env:PATH" }

Write-Host "MRML Windows oracle ready: $WindowsToolchain ($ActualCommit)"
Write-Host "Dot-source this script (`. .\tools\toolchain\setup-oracle.ps1`) to retain the environment in the current PowerShell session."
