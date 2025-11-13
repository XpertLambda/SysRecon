@echo off
REM ===================================================================
REM SysRecon Windows Installer Build Script
REM ===================================================================
REM This script builds the SysRecon installer for Windows
REM 
REM Requirements:
REM   - NSIS (Nullsoft Scriptable Install System) installed
REM   - SysRecon already compiled (sysrecon.exe in build directory)
REM   - Administrator privileges (recommended)
REM
REM Download NSIS from: https://nsis.sourceforge.io/Download
REM ===================================================================

echo ============================================
echo SysRecon Installer Build Script
echo ============================================
echo.

REM Check if NSIS is installed
set NSIS_PATH=C:\Program Files (x86)\NSIS\makensis.exe
if not exist "%NSIS_PATH%" (
    echo [ERROR] NSIS not found at: %NSIS_PATH%
    echo.
    echo Please install NSIS from: https://nsis.sourceforge.io/Download
    echo Default installation path should be: C:\Program Files (x86)\NSIS\
    echo.
    pause
    exit /b 1
)

echo [OK] NSIS found: %NSIS_PATH%
echo.

REM Check if executable exists
if not exist "build\sysrecon.exe" (
    echo [ERROR] sysrecon.exe not found in build directory
    echo.
    echo Please build the project first:
    echo   1. Run: build.bat
    echo   2. Or manually: cmake -B build -G "Visual Studio 17 2022" -A x64
    echo                   cmake --build build --config Release
    echo.
    pause
    exit /b 1
)

echo [OK] SysRecon executable found
echo.

REM Check if required files exist
if not exist "config.json" (
    echo [WARNING] config.json not found - creating default
    echo { > config.json
    echo   "verbose": false, >> config.json
    echo   "output_dir": "./reports", >> config.json
    echo   "report_format": "all" >> config.json
    echo } >> config.json
)

if not exist "LICENSE" (
    echo [WARNING] LICENSE file not found - creating placeholder
    echo Proprietary Software - All Rights Reserved > LICENSE
    echo Copyright (c) 2025 XpertLambda >> LICENSE
)

if not exist "README.md" (
    echo [ERROR] README.md not found
    echo Please ensure README.md exists in the project root
    pause
    exit /b 1
)

echo [OK] All required files found
echo.

REM Create installer
echo ============================================
echo Building Windows Installer...
echo ============================================
echo.

"%NSIS_PATH%" /V4 installer.nsi

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo Installer Build Successful!
    echo ============================================
    echo.
    echo Installer created: SysRecon-Setup-1.0.0.exe
    echo.
    echo You can now distribute this installer to users.
    echo The installer includes:
    echo   - SysRecon.exe
    echo   - Configuration files
    echo   - Documentation
    echo   - Start Menu shortcuts
    echo   - Desktop shortcut (optional)
    echo   - Uninstaller
    echo.
) else (
    echo.
    echo ============================================
    echo Installer Build FAILED!
    echo ============================================
    echo.
    echo Please check the error messages above.
    echo.
)

pause
