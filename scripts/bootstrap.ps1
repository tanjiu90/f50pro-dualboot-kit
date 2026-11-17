<#
.SYNOPSIS
    One-click Windows host bootstrap for f50pro-dualboot-kit.
    Creates an isolated Python .venv, installs pyserial/paramiko/pytest,
    fetches & SHA-256-verifies Release v1.0.0 tools, and generates an ADB RSA keypair if absent.
#>
[CmdletBinding()]
param(
    [switch]$SkipOpenClash,
    [switch]$InstallWinUsbHint
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Python) { $Python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $Python) { throw "Python 3.11+ not found in PATH." }

if (-not (Test-Path "$Root\.venv\Scripts\python.exe")) {
    & $Python -m venv "$Root\.venv"
}
$VenvPy = "$Root\.venv\Scripts\python.exe"
& $VenvPy -m pip install --upgrade pip
& $VenvPy -m pip install paramiko pyserial pytest

$FetchArgs = @("$Root\scripts\fetch_assets.py")
if ($SkipOpenClash) { $FetchArgs += '--no-openclash' }
& $VenvPy @FetchArgs

$AdbPub = Join-Path $env:USERPROFILE ".android\adbkey.pub"
if (-not (Test-Path $AdbPub)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $AdbPub) | Out-Null
    $AdbExe = "$Root\build\runtime-tools\host-tools-win64\platform-tools\adb.exe"
    if (Test-Path $AdbExe) {
        & $AdbExe keygen (Join-Path $env:USERPROFILE ".android\adbkey")
    }
}

if ($InstallWinUsbHint) {
    Write-Host "If Unisoc autodloader/BROM (1782:4D00) lacks a WinUSB driver, run Zadig or:"
    Write-Host "  .\build\runtime-tools\host-tools-win64\qmk_driver_installer\qmk_driver_installer.exe --force .\build\runtime-tools\host-tools-win64\qmk_driver_installer\unisoc_drivers.txt"
}
Write-Host "Bootstrap completed. Next: .\.venv\Scripts\python.exe scripts\kit.py preflight"
