@echo off
REM SysRecon Build Script for Windows
REM Usage: build.bat [release|debug] [clean]

setlocal enabledelayedexpansion

REM Configuration
set PROJECT_ROOT=%~dp0
set BUILD_DIR=%PROJECT_ROOT%build
set BUILD_TYPE=Release
set CLEAN_BUILD=0

REM Parse command line arguments
:parse_args
if "%1"=="debug" (
    set BUILD_TYPE=Debug
    shift
    goto parse_args
)
if "%1"=="release" (
    set BUILD_TYPE=Release
    shift
    goto parse_args
)
if "%1"=="clean" (
    set CLEAN_BUILD=1
    shift
    goto parse_args
)
if not "%1"=="" (
    shift
    goto parse_args
)

echo.
echo ================================
echo   SysRecon Windows Build Script
echo ================================
echo.
echo Build Type: %BUILD_TYPE%
echo Project Root: %PROJECT_ROOT%
echo Build Directory: %BUILD_DIR%
echo.

REM Check if Visual Studio is available
call :check_vs
if !ERRORLEVEL! neq 0 (
    echo ERROR: Visual Studio 2019 or 2022 not found!
    echo Please install Visual Studio with C++ workload.
    exit /b 1
)

REM Clean build if requested
if %CLEAN_BUILD%==1 (
    echo Cleaning previous build...
    if exist "%BUILD_DIR%" (
        rmdir /s /q "%BUILD_DIR%"
    )
)

REM Create build directory
if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
)

cd /d "%BUILD_DIR%"

REM Check for CMake
cmake --version >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo ERROR: CMake not found in PATH!
    echo Please install CMake from https://cmake.org/
    exit /b 1
)

echo Configuring project with CMake...
cmake -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
      "%PROJECT_ROOT%"

if !ERRORLEVEL! neq 0 (
    echo ERROR: CMake configuration failed!
    exit /b 1
)

echo.
echo Building SysRecon (%BUILD_TYPE%)...
cmake --build . --config %BUILD_TYPE% --parallel

if !ERRORLEVEL! neq 0 (
    echo ERROR: Build failed!
    exit /b 1
)

echo.
echo ================================
echo         BUILD SUCCESSFUL!
echo ================================
echo.
echo Executable location: %BUILD_DIR%\%BUILD_TYPE%\sysrecon.exe
echo.

REM Test the executable
echo Testing executable...
"%BUILD_DIR%\%BUILD_TYPE%\sysrecon.exe" --help >nul 2>&1
if !ERRORLEVEL! equ 0 (
    echo SUCCESS: Executable runs correctly!
) else (
    echo WARNING: Executable test failed. May need administrator privileges.
)

echo.
echo To run SysRecon:
echo   cd "%BUILD_DIR%\%BUILD_TYPE%"
echo   sysrecon.exe
echo.
echo For administrator privileges:
echo   Right-click Command Prompt → "Run as administrator"
echo   Then run the executable
echo.

goto :eof

:check_vs
REM Check for Visual Studio 2022
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)

REM Check for Visual Studio 2019
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" >nul 2>&1
    exit /b 0
)

exit /b 1
