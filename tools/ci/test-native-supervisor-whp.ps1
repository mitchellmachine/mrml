# Run the authenticated restart-request fixture on native Windows with WHP.
# This is a supervisor probe, not a live FAT32 or hardware qualification.
# Requires PowerShell 7, the pinned toolchain, and a bootstrapped MRML frontend.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($args.Count) { throw "Usage: $PSCommandPath" }

Push-Location (Join-Path $PSScriptRoot '../..')
$work = $null
try {
    $mrml = (Resolve-Path './target/debug/mrml.exe').Path
    & $mrml build org.mrml.tool.sign --target windows --release
    & $mrml build org.mrml.tool.vmm-whp-run --target windows --release
    & $mrml build org.mrml.system.service-image --target native --release
    & $mrml build org.mrml.system.bootloader --target uefi-x86_64 --release --feature-profile service_restart_request_probe

    $sign = (Resolve-Path './target/mrml-native/windows/release/mrml-sign.exe').Path
    $runner = (Resolve-Path './target/mrml-native/windows/release/mrml-whp-run.exe').Path
    $kernel = (Resolve-Path './target/mrml-native/uefi/release/mrml-kernel-pe.efi').Path
    $service = (Resolve-Path './target/mrml-native/mrml_native-x86_64-unknown-uefi/release/mrml-service-pe.efi').Path
    $work = [IO.Directory]::CreateTempSubdirectory('mrml-supervisor-').FullName
    foreach ($role in 'kernel', 'service', 'kernel-package') {
        & $sign keygen "$work/$role.private" "$work/$role.public"
    }
    & $sign sign-bundle kernel 1 $kernel "$work/kernel.private" "$work/kernel.signed"
    & $sign sign-bundle service 1 $service "$work/service.private" "$work/service.signed"
    & $mrml package create org.mrml.system.kernel kernel 1 x86_64 kernel "$work/kernel.signed" "$work/kernel.mrp" --private-key "$work/kernel-package.private"

    $start = [Diagnostics.ProcessStartInfo]::new($runner)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
        "$work/kernel.mrp", "$work/kernel-package.public", "$work/kernel.public",
        '1', 'service-restart-request-probe',
        "$work/service.signed", "$work/service.public", '1'
    )) {
        $start.ArgumentList.Add($argument)
    }
    $probe = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $probe.StandardOutput.ReadToEndAsync()
        $stderr = $probe.StandardError.ReadToEndAsync()
        if (!$probe.WaitForExit(60000)) {
            $probe.Kill()
            [void]$probe.WaitForExit(5000)
            throw 'WHP supervisor probe exceeded 60 seconds.'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $diagnostics = $stderr.GetAwaiter().GetResult()
        if ($output) { Write-Output $output.TrimEnd() }
        if ($diagnostics) { [Console]::Error.WriteLine($diagnostics.TrimEnd()) }
        if ($probe.ExitCode -ne 0 -or !$output.Contains('verified authorized CPL3 restart request under WHP:')) {
            throw "WHP supervisor probe did not confirm restart (exit $($probe.ExitCode))."
        }
    } finally {
        $probe.Dispose()
    }
} finally {
    if ($work) {
        # Delete only the known files in the newly allocated test directory.
        foreach ($name in 'kernel.private', 'service.private', 'kernel-package.private',
            'kernel.public', 'service.public', 'kernel-package.public',
            'kernel.signed', 'service.signed', 'kernel.mrp') {
            $path = Join-Path $work $name
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        [IO.Directory]::Delete($work)
    }
    Pop-Location
}
