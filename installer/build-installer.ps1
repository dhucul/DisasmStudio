<#
.SYNOPSIS
    Build the DisasmStudio installer: publish a self-contained Release, then compile the Inno Setup script.

.DESCRIPTION
    One-command installer build. Run it whenever you want a fresh setup .exe after changing the app or
    bumping the version in DisasmStudio.iss / DisasmStudio.Wpf.csproj.

        1. dotnet publish  src\DisasmStudio.Wpf  -c Release -r win-x64 --self-contained  -o installer\payload
           (self-contained, no .NET prereq; published OUT of bin\ so it never clutters the dev-run Release folder)
        2. ISCC.exe        installer\DisasmStudio.iss   (packages installer\payload)
        3. Prints the produced installer\Output\DisasmStudio-Setup-<version>.exe

    ISCC.exe (Inno Setup 6) is located automatically; pass -Iscc to point at a non-standard install.
    The compiled setup .exe lands in installer\Output\ (git-ignored). Installing over an existing
    C:\Program Files\DisasmStudio needs elevation — run the produced setup .exe yourself.

.PARAMETER SkipPublish
    Reuse the existing publish output and only re-run ISCC (fast when the binaries are already current).

.PARAMETER Iscc
    Full path to ISCC.exe, if it isn't in one of the standard Inno Setup 6 locations.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build-installer.ps1
.EXAMPLE
    .\installer\build-installer.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish,
    [string]$Iscc
)

$ErrorActionPreference = 'Stop'

# Repo root = the folder containing this script's parent (installer\ -> repo root).
$repo    = Split-Path -Parent $PSScriptRoot
$issFile = Join-Path $PSScriptRoot 'DisasmStudio.iss'
$wpfProj = Join-Path $repo 'src\DisasmStudio.Wpf'
# The self-contained payload publishes here (out of the way), NOT into bin\Release\net10.0-windows\win-x64\ — so
# it never clutters the Release folder next to the framework-dependent dev-run exe. Matches DisasmStudio.iss.
$payload = Join-Path $repo 'installer\payload'

if (-not (Test-Path $issFile)) { throw "Cannot find $issFile" }

# Read the version straight from the .iss so the message and sanity-check always match what ships.
$verLine = Get-Content $issFile | Where-Object { $_ -match '#define\s+MyAppVersion\s+"([^"]+)"' } | Select-Object -First 1
$version = if ($verLine -match '"([^"]+)"') { $Matches[1] } else { '?' }
Write-Host "DisasmStudio installer build - version $version" -ForegroundColor Cyan

$hostProj = Join-Path $repo 'src\DisasmStudio.ManagedDbgHost'

# --- 1. Publish the self-contained Release payload the installer packages ---
if ($SkipPublish) {
    Write-Host "Skipping publish (-SkipPublish); reusing existing publish output." -ForegroundColor Yellow
} else {
    # The out-of-process managed-debug hosts (one per target bitness) must be self-contained: the installed app
    # ships with no .NET prerequisite, so a framework-dependent host would fail to find a runtime on a clean
    # machine. Publish both first so the WPF publish's copy target bundles them under mdbghost\win-{arch}\.
    foreach ($rid in 'win-x64','win-x86') {
        Write-Host "`n[1/3] Publishing managed-debug host ($rid, self-contained)..." -ForegroundColor Cyan
        & dotnet publish $hostProj -c Release -r $rid --self-contained true -p:PublishTrimmed=false
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish (host $rid) failed (exit $LASTEXITCODE)." }
    }
    Write-Host "`n[2/3] Publishing self-contained Release app (win-x64) -> installer\payload ..." -ForegroundColor Cyan
    if (Test-Path $payload) { Remove-Item $payload -Recurse -Force }
    & dotnet publish $wpfProj -c Release -r win-x64 --self-contained true -o $payload `
        -p:PublishSingleFile=false -p:DebugType=none
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)." }
    # `dotnet publish -r win-x64` still emits the framework RID build under bin\Release\...\win-x64\ as a
    # byproduct; drop it so bin\Release\net10.0-windows\ holds ONLY the dev-run (framework-dependent) exe.
    Remove-Item (Join-Path $wpfProj 'bin\Release\net10.0-windows\win-x64') -Recurse -Force -ErrorAction SilentlyContinue
}

$publishDir = $payload
$exe        = Join-Path $publishDir 'DisasmStudio.exe'
if (-not (Test-Path $exe)) {
    throw "Publish output not found at $exe. Run without -SkipPublish to build it first."
}

# --- 2. Locate ISCC.exe (Inno Setup 6) ---
if (-not $Iscc) {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $Iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $Iscc -or -not (Test-Path $Iscc)) {
    throw "ISCC.exe (Inno Setup 6) not found. Install Inno Setup 6, or pass -Iscc <path to ISCC.exe>."
}
Write-Host "Using ISCC: $Iscc" -ForegroundColor DarkGray

# --- 3. Compile the installer ---
Write-Host "`n[3/3] Compiling installer..." -ForegroundColor Cyan
& $Iscc $issFile
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)." }

$setup = Join-Path $PSScriptRoot "Output\DisasmStudio-Setup-$version.exe"
if (Test-Path $setup) {
    $size = [math]::Round((Get-Item $setup).Length / 1MB, 1)
    Write-Host "`nDone. Installer: $setup ($size MB)" -ForegroundColor Green
    Write-Host "Run it yourself (elevation required to write C:\Program Files\DisasmStudio)." -ForegroundColor DarkGray
} else {
    Write-Host "`nISCC reported success but $setup was not found - check the ISCC output above." -ForegroundColor Yellow
}
