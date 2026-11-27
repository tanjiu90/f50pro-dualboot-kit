@echo off
setlocal EnableExtensions
rem Reset PSModulePath locally so child Windows PowerShell 5.1 works cleanly even when launched from PowerShell 7 (pwsh).
set "PSModulePath="
rem Use token-based privilege check instead of `net session` (which fails when LanmanServer service is stopped).
fltmc >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "exit ([int](-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Please right-click PowerShell/CMD and "Run as administrator" before installing Unisoc WinUSB drivers.
        echo [错误] 请右键以“管理员身份运行” PowerShell / 命令提示符后再安装展锐 WinUSB 驱动。
        exit /b 1
    )
)

set "REPO_ROOT=%~dp0.."
set "QMK_DIR=%REPO_ROOT%\build\runtime-tools\host-tools-win64\qmk_driver_installer"
set "INSTALLER=%QMK_DIR%\qmk_driver_installer.exe"
set "LIST=%QMK_DIR%\unisoc_drivers.txt"

if not exist "%INSTALLER%" (
    echo [ERROR] Missing "%INSTALLER%". Run .\scripts\bootstrap.ps1 first to download host-tools-win64.
    echo [错误] 未找到驱动安装器，请先运行 .\scripts\bootstrap.ps1 下载 Windows 工具包。
    exit /b 1
)
if not exist "%LIST%" (
    echo [ERROR] Missing "%LIST%". Re-run .\scripts\bootstrap.ps1 to restore host-tools-win64.
    exit /b 1
)

rem Authenticate qmk_driver_installer.exe and unisoc_drivers.txt directly against manifest-verified host-tools-win64.zip BEFORE elevated execution (pure .NET SHA-256, zero PSModulePath/Get-FileHash dependency).
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $root = (Resolve-Path $env:REPO_ROOT).Path; $m = Get-Content -Raw (Join-Path $root 'assets\release-manifest.json') | ConvertFrom-Json; $pack = $m.packs.host_tools_win64; $expZip = $pack.sha256.ToLowerInvariant(); $sha = [Security.Cryptography.SHA256]::Create(); try { $hashFile = { param($fp) $fs = [IO.File]::OpenRead($fp); try { ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-','').ToLowerInvariant() } finally { $fs.Dispose() } }; $cands = @((Join-Path $root ('bundle-cache\' + $pack.filename)), (Join-Path $root ('dist\release-' + $m.release_tag + '\' + $pack.filename))); $arc = $null; foreach($c in $cands){ if((Test-Path -LiteralPath $c) -and ((& $hashFile $c) -eq $expZip)){ $arc = $c; break } }; if(-not $arc){ Write-Error 'Authenticated host-tools-win64.zip not found or SHA-256 mismatch; run bootstrap.ps1 first.'; exit 1 }; $zf = [IO.Compression.ZipFile]::OpenRead($arc); try { foreach($pair in @(@('qmk_driver_installer/qmk_driver_installer.exe',$env:INSTALLER),@('qmk_driver_installer/unisoc_drivers.txt',$env:LIST))){ $e = $zf.GetEntry($pair[0]); if(-not $e){ Write-Error ('Missing zip entry: ' + $pair[0]); exit 1 }; $s = $e.Open(); try { $expH = ([BitConverter]::ToString($sha.ComputeHash($s)) -replace '-','').ToLowerInvariant() } finally { $s.Dispose() }; $gotH = & $hashFile $pair[1]; if($gotH -ne $expH){ Write-Error ('Integrity mismatch on ' + $pair[0] + '; refusing elevated execution.'); exit 1 } } } finally { $zf.Dispose() } } finally { $sha.Dispose() }; Write-Host '[OK] Authenticated qmk_driver_installer.exe and unisoc_drivers.txt against release-manifest.json.'"
if errorlevel 1 (
    exit /b %errorlevel%
)

echo Pre-installing Unisoc BROM (1782:4D00) and Boot Diag (1782:4D03) WinUSB drivers (--force --all)...
"%INSTALLER%" --force --all "%LIST%"
set "INST_RC=%errorlevel%"
if not "%INST_RC%"=="0" (
    echo [ERROR] qmk_driver_installer exited with code %INST_RC%.
    exit /b %INST_RC%
)

rem Verify BOTH 1782:4D00 and 1782:4D03 WinUSB INFs (UTF-8 or UTF-16LE BOM) landed in Windows Driver Store AND no live BROM device is bound to a non-WinUSB driver.
powershell -NoProfile -Command "$out = pnputil /enum-drivers 2>$null | Out-String; $infs = [regex]::Matches($out, '\boem\d+\.inf\b', 'IgnoreCase') | ForEach-Object { $_.Value } | Sort-Object -Unique; $has4d00=$false; $has4d03=$false; foreach($n in $infs){ $p = Join-Path $env:WINDIR ('INF\' + $n); if(-not (Test-Path $p)){ continue }; $bytes = [IO.File]::ReadAllBytes($p); if($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE){ $txt = [Text.Encoding]::Unicode.GetString($bytes) } elseif($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF){ $txt = [Text.Encoding]::BigEndianUnicode.GetString($bytes) } else { $txt = [Text.Encoding]::UTF8.GetString($bytes) }; $u = $txt.ToUpperInvariant(); if($u -match 'WINUSB\.INF|LIBWDI|WINUSB\.NT'){ if($u.Contains('VID_1782&PID_4D00')){ $has4d00=$true }; if($u.Contains('VID_1782&PID_4D03')){ $has4d03=$true } } }; $liveBad = @(); try { $brom = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.PNPDeviceID -match 'VID_1782&PID_(4D00|4D03)' }); foreach($d in $brom){ $svc = [string]$d.Service; $ec = [int]$d.ConfigManagerErrorCode; if($ec -ne 0 -or ($svc.ToLowerInvariant() -notin @('winusb','libusbk','libusb0'))){ $liveBad += ($svc + ':' + $ec) } } } catch { Write-Error 'Live PnP verification failed'; exit 1 }; if($has4d00 -and $has4d03 -and $liveBad.Count -eq 0){ Write-Host '[OK] Verified both 1782:4D00 and 1782:4D03 WinUSB drivers in Windows Driver Store (no live binding conflicts).'; exit 0 } else { Write-Error ('Driver verification failed: 4D00=' + $has4d00 + ', 4D03=' + $has4d03 + ', liveConflicts=' + ($liveBad -join ';')); exit 1 }"
exit /b %errorlevel%
