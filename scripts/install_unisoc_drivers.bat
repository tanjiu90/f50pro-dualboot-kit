@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please right-click PowerShell/CMD and "Run as administrator" before installing Unisoc WinUSB drivers.
    echo [错误] 请右键以“管理员身份运行” PowerShell / 命令提示符后再安装展锐 WinUSB 驱动。
    exit /b 1
)

set "QMK_DIR=%~dp0..\build\runtime-tools\host-tools-win64\qmk_driver_installer"
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

echo Pre-installing Unisoc BROM (1782:4D00) and Boot Diag (1782:4D03) WinUSB drivers (--force --all)...
"%INSTALLER%" --force --all "%LIST%"
exit /b %errorlevel%
