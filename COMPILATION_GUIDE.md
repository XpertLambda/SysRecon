# SysRecon Compilation & Usage Guide

## 📋 Table of Contents
- [Prerequisites](#prerequisites)
- [Compilation on Arch Linux (Cross-compilation)](#compilation-on-arch-linux-cross-compilation)
- [Compilation on Windows](#compilation-on-windows)
- [Usage Instructions](#usage-instructions)
- [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

### For Arch Linux (Cross-compilation to Windows)
```bash
# Install MinGW-w64 toolchain
sudo pacman -S mingw-w64-gcc mingw-w64-cmake

# Install build tools
sudo pacman -S cmake make ninja

# Optional: For debugging and analysis
sudo pacman -S gdb-multiarch wine
```

### For Windows (Native compilation)
- **Visual Studio 2022** (Community Edition or higher) with C++ workload
- **CMake** (3.20 or higher) - Download from https://cmake.org/
- **Git for Windows** - Download from https://git-scm.com/
- **Windows SDK** (10.0.19041.0 or higher)

---

## 🐧 Compilation on Arch Linux (Cross-compilation)

### Method 1: Using CMake (Recommended)
```bash
# Navigate to project directory
cd /path/to/SysRecon

# Create build directory
mkdir -p build
cd build

# Configure with MinGW-w64 toolchain
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -S .. -B .

# Build the project
make -j$(nproc)

# Alternative: Using ninja for faster builds
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -GNinja \
      -S .. -B .
ninja
```

### Method 2: Using Makefile
```bash
# Navigate to project directory
cd /path/to/SysRecon

# Build release version
make

# Build debug version
make DEBUG=1

# Clean build
make clean

# Install (copies to /usr/local/bin)
sudo make install
```

### Method 3: Using Build Script
```bash
# Make build script executable
chmod +x build.sh

# Run build script
./build.sh

# For debug build
./build.sh debug
```

### Verification
```bash
# Check if executable was created
ls -la build/sysrecon.exe

# Test with Wine (optional)
wine build/sysrecon.exe --help
```

---

## 🪟 Compilation on Windows

### Method 1: Visual Studio (GUI)
1. **Open Visual Studio 2022**
2. **File → Open → CMake...**
3. **Select** `CMakeLists.txt` from the SysRecon directory
4. **Wait** for CMake to configure the project
5. **Build → Build All** (or press `Ctrl+Shift+B`)
6. **Executable** will be in `out/build/x64-Release/`

### Method 2: Command Line (Developer Command Prompt)
```cmd
:: Open "Developer Command Prompt for VS 2022"
cd C:\path\to\SysRecon

:: Create build directory
mkdir build
cd build

:: Configure with CMake
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release ..

:: Build the project
cmake --build . --config Release --parallel

:: Alternative: Using MSBuild directly
msbuild SysRecon.sln /p:Configuration=Release /p:Platform=x64 /m
```

### Method 3: MinGW-w64 on Windows
```cmd
:: Install MSYS2 first: https://www.msys2.org/
:: Open MSYS2 terminal

:: Install MinGW-w64
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make

:: Navigate to project
cd /c/path/to/SysRecon

:: Build with MinGW
mkdir build
cd build
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..
mingw32-make -j4
```

---

## 🚀 Usage Instructions

### Basic Usage
```cmd
:: Display help
sysrecon.exe --help

:: Run basic scan
sysrecon.exe

:: Run with verbose output
sysrecon.exe --verbose

:: Run in stealth mode
sysrecon.exe --stealth
```

### Advanced Usage
```cmd
:: Specify output directory
sysrecon.exe --output C:\Reports\

:: Choose specific modules
sysrecon.exe --modules accounts,services,processes

:: Set output format
sysrecon.exe --format json,html

:: Run quick scan only
sysrecon.exe --quick

:: Custom configuration file
sysrecon.exe --config custom_config.json

:: Full security audit
sysrecon.exe --full --output C:\Audit\ --format all
```

### Configuration File Example (`config.json`)
```json
{
  "general": {
    "verbose_output": true,
    "stealth_mode": false,
    "require_admin": true,
    "max_threads": 4,
    "timeout_seconds": 300
  },
  "modules": {
    "accounts": {
      "enabled": true,
      "enumerate_groups": true,
      "check_passwords": false,
      "analyze_permissions": true
    },
    "services": {
      "enabled": true,
      "analyze_startup": true,
      "check_dependencies": true,
      "verify_signatures": false
    },
    "processes": {
      "enabled": true,
      "analyze_memory": false,
      "check_dlls": true,
      "detect_injection": true
    },
    "network": {
      "enabled": true,
      "scan_listening_ports": true,
      "analyze_connections": true,
      "resolve_hostnames": false
    },
    "registry": {
      "enabled": true,
      "scan_startup_keys": true,
      "analyze_policies": true,
      "check_permissions": true
    },
    "memory": {
      "enabled": false,
      "create_dumps": false,
      "analyze_heap": false,
      "scan_for_malware": true,
      "max_dump_size_mb": 100
    }
  },
  "output": {
    "output_directory": "./reports",
    "generate_json": true,
    "generate_csv": true,
    "generate_html": true,
    "generate_pdf": false,
    "compress_output": true
  },
  "security": {
    "encrypt_output": false,
    "sign_reports": false
  }
}
```

### Running with Administrator Privileges
```cmd
:: Run as Administrator (required for full functionality)
:: Right-click Command Prompt → "Run as administrator"
cd C:\path\to\sysrecon
sysrecon.exe --full
```

### PowerShell Usage
```powershell
# Run from PowerShell (as Administrator)
Set-Location "C:\path\to\sysrecon"
.\sysrecon.exe --modules accounts,services --format json --output .\results\

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host "Scan completed successfully" -ForegroundColor Green
} else {
    Write-Host "Scan failed with code: $LASTEXITCODE" -ForegroundColor Red
}
```

### Automated Scanning (Task Scheduler)
```cmd
:: Create scheduled task for regular audits
schtasks /create /tn "SysRecon Daily Audit" /tr "C:\Tools\sysrecon.exe --quick --output C:\Audits\" /sc daily /st 02:00 /ru SYSTEM
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. **Permission Denied Errors**
```cmd
:: Solution: Run as Administrator
runas /user:Administrator "cmd /c sysrecon.exe"
```

#### 2. **Missing DLL Errors on Linux**
```bash
# Install Wine dependencies
sudo pacman -S wine wine-gecko wine-mono

# Install Windows runtime libraries
winetricks vcrun2019 vcrun2022
```

#### 3. **Compilation Errors**
```bash
# Update MinGW-w64
sudo pacman -Syu mingw-w64-gcc

# Clean and rebuild
make clean
make
```

#### 4. **CMake Configuration Issues**
```bash
# Clear CMake cache
rm -rf build/
mkdir build && cd build

# Reconfigure
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake ..
```

### Debug Build
```bash
# Compile with debug symbols
make DEBUG=1

# Run with GDB
gdb --args wine build/sysrecon.exe
```

### Performance Tuning
```cmd
:: Limit thread usage for resource-constrained systems
sysrecon.exe --config config.json

:: In config.json, set:
:: "max_threads": 2
:: "timeout_seconds": 600
```

---

## 📊 Output Interpretation

### Exit Codes
- `0`: Success
- `1`: General error
- `2`: Permission denied
- `3`: Configuration error
- `4`: Module initialization failed
- `5`: Scan interrupted

### Report Files
- `scan_results.json`: Machine-readable results
- `scan_report.html`: Human-readable web report
- `scan_summary.csv`: Spreadsheet-compatible data
- `scan_executive.pdf`: Executive summary (if enabled)

### Log Files
- `sysrecon.log`: Detailed execution log
- `errors.log`: Error messages and warnings
- `debug.log`: Debug information (debug builds only)

---

## 🛡️ Security Considerations

1. **Run with appropriate privileges**: Administrator rights required for full functionality
2. **Secure storage**: Protect output files containing sensitive system information
3. **Network isolation**: Consider running on isolated systems for sensitive environments
4. **Data retention**: Implement proper data retention policies for scan results
5. **Encryption**: Enable output encryption for sensitive environments

---

## 📞 Support

For technical support or questions:
- Review the [Project Documentation](README.md)
- Check [Issue Tracker](https://github.com/XpertLambda/SysRecon/issues)
- Contact: support@sysrecon.dev

---

**⚠️ Disclaimer**: This tool is designed for authorized security testing and system administration only. Users are responsible for compliance with applicable laws and regulations.
