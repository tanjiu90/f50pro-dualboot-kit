<#
.SYNOPSIS
    One-click Windows host bootstrap for f50pro-dualboot-kit with selectable release packs.
    Creates an isolated Python .venv, installs pyserial/paramiko/pytest,
    fetches & SHA-256-verifies selected Release packs, and generates an ADB RSA keypair if absent.
#>
[CmdletBinding()]
param(
    [string]$HostPlatform = "auto",
    [string]$Profile = "all",
    [string[]]$Packs,
    [switch]$SkipOpenClash,
    [switch]$ListPacks,
    [switch]$Interactive,
    [switch]$InstallWinUsbHint
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$ArgList
    )
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($ArgList -join ' ')"
    }
}

$Python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Python) { $Python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $Python) { throw "Python 3.11+ not found in PATH." }

if ($ListPacks) {
    & $Python "$Root\scripts\fetch_assets.py" --list-packs
    exit $LASTEXITCODE
}

if (-not (Test-Path "$Root\.venv\Scripts\python.exe")) {
    Invoke-Checked -Exe $Python -ArgList @('-m', 'venv', "$Root\.venv")
}
$VenvPy = "$Root\.venv\Scripts\python.exe"
Invoke-Checked -Exe $VenvPy -ArgList @('-m', 'pip', 'install', '--upgrade', 'pip')
Invoke-Checked -Exe $VenvPy -ArgList @('-m', 'pip', 'install', 'paramiko', 'pyserial', 'pytest')

$FetchArgs = @("$Root\scripts\fetch_assets.py")
if ($Interactive) {
    $FetchArgs += '--interactive'
} else {
    $FetchArgs += @('--host-platform', $HostPlatform, '--profile', $Profile)
    if ($Packs -and $Packs.Count -gt 0) {
        $FetchArgs += '--packs'
        $FetchArgs += $Packs
    }
    if ($SkipOpenClash) { $FetchArgs += '--no-openclash' }
}
Invoke-Checked -Exe $VenvPy -ArgList $FetchArgs

$AdbPub = Join-Path $env:USERPROFILE ".android\adbkey.pub"
if (-not (Test-Path $AdbPub)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $AdbPub) | Out-Null
    $AdbExe = "$Root\build\runtime-tools\host-tools-win64\platform-tools\adb.exe"
    if (-not (Test-Path $AdbExe)) {
        $Cmd = Get-Command adb -ErrorAction SilentlyContinue
        if ($Cmd) { $AdbExe = $Cmd.Source }
    }
    if ($AdbExe -and (Test-Path $AdbExe)) {
        Invoke-Checked -Exe $AdbExe -ArgList @('keygen', (Join-Path $env:USERPROFILE ".android\adbkey"))
    }
}

if ($InstallWinUsbHint) {
    Write-Host "Recommended (runs --force --all AND verifies 1782:4D00 & 1782:4D03 in Windows Driver Store + live binding, run as Administrator):"
    Write-Host "  .\scripts\install_unisoc_drivers.bat"
    Write-Host "Note: running qmk_driver_installer.exe --force --all unisoc_drivers.txt directly only invokes the raw installer; always verify Driver Store registration and live WinUSB binding (use Zadig if a serial driver claims 1782:4D00)."
}
Write-Host "Bootstrap completed (host dependencies & SHA-256 verified packs staged; physical USB communication is not yet tested). Next: run .\scripts\install_unisoc_drivers.bat (Admin, first time), then .\.venv\Scripts\python.exe scripts\kit.py preflight"
