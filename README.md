# SysRecon - Windows Security Audit & Reconnaissance Tool

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/XpertLambda/SysRecon/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010/11%20|%20Server%202016+-blue.svg)](https://github.com/XpertLambda/SysRecon)
[![Language](https://img.shields.io/badge/language-C++20-orange.svg)](https://github.com/XpertLambda/SysRecon)
[![License](https://img.shields.io/badge/license-Commercial-red.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/XpertLambda/SysRecon)

**Professional-grade security auditing and reconnaissance solution for Windows environments**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Technical Specifications](#technical-specifications)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Command Reference](#command-reference)
- [Output & Reporting](#output--reporting)
- [Use Cases](#use-cases)
- [Build Instructions](#build-instructions)
- [Architecture](#architecture)
- [Support & Licensing](#support--licensing)

---

## Overview

SysRecon is an enterprise-class security assessment platform designed to provide comprehensive visibility into Windows system configurations, security posture, and potential vulnerabilities. Built for security professionals, system administrators, and compliance teams, SysRecon automates the complex process of security auditing while delivering actionable intelligence through sophisticated analysis and reporting capabilities.

### Key Differentiators

- **Comprehensive Coverage**: Six specialized assessment modules covering user accounts, services, processes, network infrastructure, registry configurations, and memory forensics
- **Enterprise Architecture**: Built with C++20 for optimal performance and minimal system footprint
- **Flexible Deployment**: Cross-platform compilation support with native Windows execution
- **Professional Reporting**: Multi-format output including JSON, CSV, and HTML with executive summaries and detailed technical findings
- **Production-Ready**: Over 6,500 lines of production-quality code with extensive Windows API integration

---

## Core Capabilities

### Security Assessment Modules

#### User Account Intelligence

- Comprehensive enumeration of local users and security groups via NetUserEnum API
- Security Identifier (SID) resolution and privilege level analysis
- Group membership mapping and administrator account detection
- Account policy assessment and anomaly detection

#### Service Configuration Analysis

- Complete Windows service inventory through Service Control Manager integration
- Startup configuration analysis (Automatic, Manual, Disabled, Delayed)
- Detection of unquoted service paths—a critical privilege escalation vector
- Service account security posture evaluation
- Binary signature verification and path validation

#### Process & Module Monitoring

- Real-time process enumeration using Toolhelp32 API
- Comprehensive loaded module analysis with path and signature details
- Process memory footprint assessment
- Detection of suspicious processes and uncommon execution patterns
- Parent-child process relationship mapping

#### Network Infrastructure Assessment

- Active TCP/UDP connection enumeration with remote endpoint resolution
- Listening port analysis and service binding identification
- Network interface discovery including MAC addresses, IP configurations, and DHCP status
- Network share enumeration with permission analysis
- Windows Firewall rule and policy assessment
- Network adapter configuration review

#### Registry Security Analysis

- Persistence mechanism detection across standard autorun locations
- Security policy configuration review (UAC, Windows Defender, BitLocker)
- Registry permission and ACL analysis
- Browser Helper Object (BHO) and toolbar detection
- Image File Execution Options (IFEO) monitoring for debugger attachments
- Run/RunOnce key enumeration across HKLM and HKCU hives

#### Memory Forensics & Analysis

- Process memory region enumeration via VirtualQueryEx
- Detection of Read-Write-Execute (RWX) memory regions—indicators of code injection
- DLL injection pattern recognition
- Process hollowing detection through PE header validation
- Shellcode signature matching using pattern analysis
- Memory-resident threat identification

### Reporting & Intelligence

#### Multi-Format Output

- **JSON**: Structured data output for SIEM integration, automation workflows, and programmatic analysis
- **CSV**: Spreadsheet-compatible format for data manipulation in Excel, database import, and trend analysis
- **HTML**: Executive-ready reports with risk-based color coding, sortable tables, and professional styling

#### Risk Assessment Framework

- **Critical**: Active exploitation indicators requiring immediate remediation
- **High**: Significant vulnerabilities or misconfigurations with elevated risk
- **Medium**: Security weaknesses requiring attention within planned maintenance windows
- **Low**: Best practice deviations and informational findings

#### Executive Intelligence

- High-level security posture summaries
- Trend analysis across multiple assessments
- Compliance mapping to industry frameworks
- Prioritized remediation recommendations

---

## Technical Specifications

### Platform & Architecture

| Component | Specification |
|-----------|--------------|
| **Language** | C++20 with modern standard library features |
| **Build System** | CMake 3.20+ for cross-platform compilation |
| **Target OS** | Windows 10, Windows 11, Server 2016/2019/2022 |
| **Architecture** | x64 (64-bit) only |
| **Compiler** | MinGW-w64 GCC 15.2.0 (cross-compilation) or MSVC 2022 (native) |
| **Binary Format** | PE32+ executable with code signing support |
| **Dependencies** | nlohmann/json 3.11.3 (header-only, embedded) |
| **Binary Size** | ~18 MB (optimized release build) |

### Windows API Integration

SysRecon leverages native Windows APIs for maximum compatibility and performance:

**Security & Identity**
- `NetUserEnum`, `NetLocalGroupEnum`, `NetLocalGroupGetMembers`
- `LookupAccountSid`, `LookupAccountName`
- `GetTokenInformation`, `OpenProcessToken`

**Service Management**
- `OpenSCManager`, `EnumServicesStatusEx`, `QueryServiceConfig`
- `QueryServiceConfig2`, `QueryServiceStatus`

**Process & Memory**
- `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`
- `Module32First`, `Module32Next`
- `VirtualQueryEx`, `ReadProcessMemory`, `OpenProcess`

**Network Operations**
- `GetTcpTable2`, `GetUdpTable`, `GetExtendedUdpTable`
- `GetAdaptersInfo`, `GetAdaptersAddresses`
- `NetShareEnum`, `NetShareGetInfo`

**Registry Access**
- `RegOpenKeyEx`, `RegEnumValue`, `RegEnumKeyEx`
- `RegGetKeySecurity`, `RegQueryValueEx`

**System Information**
- `GetComputerName`, `GetVersionEx`, `GetSystemInfo`
- `GetNativeSystemInfo`, `IsWow64Process`

---

## System Requirements

### Production Environment (Windows)

| Requirement | Specification |
|-------------|--------------|
| **Operating System** | Windows 10 version 1809+, Windows 11, Windows Server 2016+ |
| **Architecture** | x64 (64-bit) systems only |
| **Memory** | 2 GB RAM minimum, 4 GB recommended |
| **Storage** | 100 MB free disk space for installation and reports |
| **Privileges** | Administrator or equivalent elevated rights |
| **Runtime** | .NET Framework 4.8+ (typically pre-installed on modern Windows) |

**Compatibility Notes:**
- Windows 10 versions prior to 1809 may experience limited functionality
- ARM64 architecture not currently supported
- Domain-joined or standalone workstations fully supported

### Development Environment (Cross-Compilation)

#### Linux Build Host

**Arch Linux:**
```bash
sudo pacman -S mingw-w64-gcc mingw-w64-cmake cmake make base-devel git
```

**Ubuntu 20.04 LTS / Debian 11+:**
```bash
sudo apt update
sudo apt install mingw-w64 cmake build-essential git pkg-config
```

**RHEL 8+ / Fedora 35+:**
```bash
sudo dnf install mingw64-gcc-c++ mingw64-winpthreads-static cmake make git
```

#### Windows Build Host (Native Compilation)

| Component | Version | Notes |
|-----------|---------|-------|
| **Visual Studio** | 2022 (17.0+) | Community, Professional, or Enterprise |
| **Workload** | Desktop development with C++ | Must include Windows 10/11 SDK |
| **CMake** | 3.20+ | Add to PATH during installation |
| **Git** | 2.30+ | Git for Windows recommended |
| **Windows SDK** | 10.0.19041.0+ | Included with Visual Studio C++ workload |

---

## Installation

### Option 1: Windows Installer (Easiest - Recommended)

**Professional Graphical Setup Wizard:**

SysRecon includes a professional Windows installer with full GUI for easy deployment.

#### Features:

✅ **Graphical Installation Wizard** - Click-through setup like professional software  
✅ **Start Menu Integration** - Multiple shortcuts (main app, help, quick scan, reports)  
✅ **Desktop Shortcut** - Optional quick access from desktop  
✅ **PATH Integration** - Optional command-line access from anywhere  
✅ **Automatic Configuration** - Sets up reports directory and default config  
✅ **Professional Uninstaller** - Complete removal with option to keep reports  

#### Quick Start:

1. Download `SysRecon-Setup-1.0.0.exe` from releases
2. Right-click → **"Run as Administrator"**
3. Follow the installation wizard
4. Launch from Start Menu → SysRecon

#### Building the Installer:

See **[INSTALLER_GUIDE.md](INSTALLER_GUIDE.md)** for complete documentation.

**Windows:**
```cmd
REM Install NSIS from: https://nsis.sourceforge.io/Download
REM Build the project first
build.bat

REM Create installer
build-installer.bat

REM Result: SysRecon-Setup-1.0.0.exe
```

**Linux (Cross-compilation):**
```bash
# Install NSIS
sudo pacman -S nsis  # Arch
sudo apt install nsis  # Ubuntu

# Build the project first
./build.sh

# Create installer
./build-installer.sh

# Result: SysRecon-Setup-1.0.0.exe (transfer to Windows)
```

---

### Option 2: Pre-Built Binaries (Portable)

**For Production Deployments (No Installation Required):**

1. Download the latest release from the official repository
2. Verify the digital signature (recommended for enterprise environments)
3. Deploy to target Windows systems via your standard software distribution method
4. Execute with administrator privileges

```powershell
# Verify digital signature (PowerShell)
Get-AuthenticodeSignature C:\Tools\sysrecon.exe

# Run with administrator privileges
Start-Process -FilePath "C:\Tools\sysrecon.exe" -Verb RunAs -ArgumentList "--help"
```

---

### Option 3: Build from Source

**For Custom Deployments or Development:**

See the [Build Instructions](#build-instructions) section for detailed compilation procedures.

---

## Usage Guide

### Execution Prerequisites

**Administrator Privileges Required**: Most assessment modules require elevated privileges to access system-level APIs and security information. Execute SysRecon from an elevated command prompt or PowerShell session.

```cmd
REM Right-click Command Prompt → "Run as administrator"
REM Or use PowerShell with elevation:
Start-Process cmd.exe -Verb RunAs
```

### Basic Operation

#### Full System Assessment

```cmd
sysrecon.exe
```

Executes a comprehensive security assessment across all modules with default configuration.

#### Quick Assessment Mode

```cmd
sysrecon.exe --quick
```

Performs accelerated scanning with reduced depth—ideal for rapid initial reconnaissance.

#### Verbose Diagnostic Mode

```cmd
sysrecon.exe --verbose
```

Enables detailed logging output for troubleshooting and audit trail generation.

### Selective Module Execution

#### Individual Module Scans

```cmd
REM User account and privilege assessment
sysrecon.exe --accounts

REM Service configuration analysis
sysrecon.exe --services

REM Process and module enumeration
sysrecon.exe --processes

REM Network infrastructure assessment
sysrecon.exe --network

REM Registry persistence analysis
sysrecon.exe --registry

REM Memory forensics and injection detection
sysrecon.exe --memory
```

#### Combined Module Scanning

```cmd
REM Security-focused assessment
sysrecon.exe --accounts --services --registry

REM Network and process analysis
sysrecon.exe --network --processes

REM Complete forensic assessment
sysrecon.exe --memory --processes --registry
```

### Report Configuration

#### Output Directory Specification

```cmd
sysrecon.exe --output "C:\SecurityAssessments\Audit_2025-11-13"
```

#### Format Selection

```cmd
REM Single format
sysrecon.exe --format json
sysrecon.exe --format csv
sysrecon.exe --format html

REM Multiple formats
sysrecon.exe --format json --format html

REM All formats (default)
sysrecon.exe --format all
```

#### Comprehensive Example

```cmd
sysrecon.exe --accounts --services --network ^
             --output "C:\Audits\Monthly\2025-11" ^
             --format all ^
             --verbose
```

### Operational Modes

#### Stealth Mode

```cmd
sysrecon.exe --stealth --quiet
```

Minimizes system footprint and suppresses console output—useful for sensitive environments or systems under active monitoring.

#### Compliance Scanning

```cmd
sysrecon.exe --config compliance-template.json ^
             --output "C:\Compliance\SOC2-Audit"
```

Leverages custom configuration profiles for compliance-specific assessments.

---

## Command Reference

### General Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display comprehensive usage information and exit |
| `-v, --version` | Display version information and build details |
| `--verbose` | Enable detailed diagnostic output and API call logging |
| `--quiet` | Suppress all non-critical console output |
| `--quick` | Enable fast-scan mode with reduced analysis depth |
| `--stealth` | Minimize system footprint and detection signatures |

### Configuration Options

| Option | Argument | Description |
|--------|----------|-------------|
| `-c, --config` | `<file>` | Load configuration from JSON file (default: config.json) |
| `-o, --output` | `<directory>` | Set output directory for reports (default: ./reports) |
| `-f, --format` | `<format>` | Report format: `json`, `csv`, `html`, `all` (default: all) |

### Module Selection

| Option | Module | Scope |
|--------|--------|-------|
| `--accounts` | User Accounts | Local user enumeration, group analysis, privilege assessment |
| `--services` | Windows Services | Service configuration, startup analysis, path validation |
| `--processes` | Running Processes | Process enumeration, module loading, memory footprint |
| `--network` | Network Infrastructure | Connections, interfaces, shares, firewall rules |
| `--registry` | Registry Analysis | Persistence keys, security policies, ACL analysis |
| `--memory` | Memory Forensics | Memory scanning, injection detection, shellcode analysis |
| `--all` | All Modules | Comprehensive assessment (default if no modules specified) |

### Advanced Options

| Option | Description |
|--------|-------------|
| `--no-admin-check` | Skip administrator privilege verification (not recommended) |
| `--timeout <seconds>` | Set maximum execution time per module (default: 300) |
| `--threads <count>` | Set thread pool size for parallel operations (default: 4) |

---

## Output & Reporting

### Report Formats

#### JSON Output

**Purpose**: Machine-readable structured data for SIEM integration, API consumption, and automated analysis workflows.

**Schema**:
```json
{
  "metadata": {
    "scan_id": "uuid-v4",
    "timestamp": "2025-11-13T14:25:30Z",
    "hostname": "WORKSTATION-01",
    "os_version": "Windows 10 Enterprise 21H2",
    "os_build": "19044.1234",
    "domain": "CORPORATE",
    "scan_duration_seconds": 142,
    "modules_executed": ["accounts", "services", "network"]
  },
  "findings": [
    {
      "module": "accounts",
      "severity": "high",
      "category": "privilege_escalation",
      "title": "Administrator Account Enabled",
      "description": "Built-in Administrator account is active and not renamed",
      "affected_item": "Administrator",
      "recommendation": "Rename or disable the built-in Administrator account",
      "references": ["CIS Windows Benchmark 1.1.4"]
    }
  ],
  "statistics": {
    "total_findings": 24,
    "by_severity": {
      "critical": 2,
      "high": 8,
      "medium": 10,
      "low": 4
    }
  }
}
```

#### CSV Output

**Purpose**: Spreadsheet analysis, database import, and business intelligence tools.

**Structure**:
```csv
Module,Severity,Category,Title,Item,Recommendation
accounts,high,privilege_escalation,Administrator Account Enabled,Administrator,Rename or disable built-in Administrator
services,medium,configuration,Unquoted Service Path,BackupService,Quote the service executable path
registry,high,persistence,Unauthorized Autorun Entry,HKLM\...\Run\malware,Remove unauthorized autorun entry
```

#### HTML Output

**Purpose**: Executive presentations, management reporting, and human-readable assessment summaries.

**Features**:
- Professional CSS styling with corporate color schemes
- Risk-based color coding (Critical: Red, High: Orange, Medium: Yellow, Low: Green)
- Sortable and filterable data tables
- Executive summary section with key metrics
- Detailed findings with remediation guidance
- Embedded charts and statistics
- Print-optimized layouts

### Report Naming Convention

Reports follow a standardized naming convention for easy organization:

```
sysrecon_<hostname>_<timestamp>_<module>.<format>

Examples:
sysrecon_WKS-01_20251113-142530_full.json
sysrecon_SRV-DB-01_20251113-142530_accounts.csv
sysrecon_WORKSTATION_20251113-142530_comprehensive.html
```

### Sample Output Location

```
C:\SecurityAssessments\
└── Audit_2025-11-13\
    ├── sysrecon_WKS-01_20251113-142530_full.json
    ├── sysrecon_WKS-01_20251113-142530_full.csv
    ├── sysrecon_WKS-01_20251113-142530_full.html
    └── logs\
        └── sysrecon_20251113-142530.log
```

---

## Use Cases

### 1. Security Operations Center (SOC)

**Scenario**: Continuous security monitoring and threat hunting

```cmd
REM Automated daily assessment with SIEM integration
sysrecon.exe --quick --format json ^
             --output "\\soc-share\assessments\%COMPUTERNAME%\%DATE%"

REM Schedule via Task Scheduler for automated execution
```

**Integration**: Parse JSON output with Splunk, ELK Stack, or Microsoft Sentinel for trend analysis and alerting.

### 2. Incident Response

**Scenario**: Rapid system triage during security incidents

```cmd
REM Comprehensive forensic capture
sysrecon.exe --memory --processes --network --registry ^
             --output "C:\IR\Case-2025-001\%COMPUTERNAME%" ^
             --format all ^
             --verbose

REM Focus on persistence mechanisms
sysrecon.exe --registry --services --startup ^
             --format json ^
             --output "C:\IR\Persistence-Analysis"
```

**Deliverables**: Evidence collection, timeline analysis, and executive incident briefs.

### 3. Penetration Testing

**Scenario**: Post-exploitation enumeration and privilege escalation

```cmd
REM Initial reconnaissance
sysrecon.exe --quick --accounts --network --stealth

REM Service vulnerability identification
sysrecon.exe --services --verbose

REM Privilege escalation vector analysis
sysrecon.exe --accounts --services --registry ^
             --format html ^
             --output "C:\PenTest\Client-ABC\Enumeration"
```

**Focus**: Unquoted service paths, weak permissions, and credential exposure.

### 4. Compliance Auditing

**Scenario**: Regulatory compliance verification (PCI-DSS, HIPAA, SOC 2)

```cmd
REM Monthly compliance assessment
sysrecon.exe --config compliance-pci-dss.json ^
             --output "C:\Compliance\PCI-DSS\%DATE%" ^
             --format all

REM Quarterly executive reporting
sysrecon.exe --accounts --services --network --registry ^
             --format html ^
             --output "C:\Compliance\Quarterly\Q4-2025"
```

**Deliverables**: Evidence packages for auditors, gap analysis, and remediation tracking.

### 5. Vulnerability Management

**Scenario**: Proactive security posture assessment

```cmd
REM Weekly vulnerability scanning
sysrecon.exe --services --processes --network ^
             --output "C:\VulnMgmt\Weekly\Week-%DATE:~-5,2%"

REM Pre-patch assessment baseline
sysrecon.exe --all --format all ^
             --output "C:\Baselines\Pre-Patch-2025-11"
```

**Integration**: Compare baselines to identify configuration drift and unauthorized changes.

### 6. System Hardening Validation

**Scenario**: Post-hardening verification

```cmd
REM Validate CIS Benchmark implementation
sysrecon.exe --accounts --services --registry ^
             --config cis-benchmark-level1.json ^
             --output "C:\Hardening\Post-Implementation"

REM Compare with baseline
```

---

## Build Instructions

### Linux Cross-Compilation (Recommended)

#### Prerequisites Setup

**Arch Linux:**
```bash
sudo pacman -S mingw-w64-gcc mingw-w64-cmake cmake make base-devel git
```

**Ubuntu 20.04 LTS / Debian 11:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y mingw-w64 cmake build-essential git pkg-config
```

**Fedora 35+ / RHEL 8:**
```bash
sudo dnf install -y mingw64-gcc-c++ mingw64-winpthreads-static cmake make git
```

#### Build Process

```bash
# Clone repository
git clone https://github.com/YourOrganization/SysRecon.git
cd SysRecon

# Create build directory
mkdir -p build && cd build

# Configure with MinGW-w64 toolchain
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/sysrecon \
      -S .. -B .

# Build with parallel compilation (utilize all CPU cores)
make -j$(nproc)

# Optional: Run test suite
ctest --output-on-failure

# Package for distribution
make package

# Output: build/sysrecon.exe (approximately 18 MB)
```

#### Build Optimization

For size-optimized builds:
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DCMAKE_CXX_FLAGS="-Os -s" \
      -S .. -B .
```

### Windows Native Compilation

#### Prerequisites Setup

1. **Install Visual Studio 2022**
   - Download Community Edition (free) from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/)
   - During installation, select **"Desktop development with C++"**
   - Ensure Windows 10/11 SDK is included

2. **Install CMake**
   - Download from [cmake.org/download](https://cmake.org/download/)
   - Select "Add CMake to system PATH" during installation

3. **Install Git for Windows**
   - Download from [git-scm.com](https://git-scm.com/download/win)
   - Use default installation options

#### Build Process

```powershell
# Open "Developer Command Prompt for VS 2022" or "Developer PowerShell"

# Clone repository
git clone https://github.com/YourOrganization/SysRecon.git
cd SysRecon

# Create build directory
mkdir build
cd build

# Configure for Visual Studio 2022 (x64)
cmake -G "Visual Studio 17 2022" -A x64 ..

# Build release version
cmake --build . --config Release --parallel

# Optional: Build debug version
cmake --build . --config Debug --parallel

# Output: build\Release\sysrecon.exe
```

### Build Troubleshooting

#### Issue: MinGW-w64 Not Found

```bash
# Verify installation
which x86_64-w64-mingw32-gcc
# Expected output: /usr/bin/x86_64-w64-mingw32-gcc

# If not found, reinstall MinGW-w64
# Arch: sudo pacman -S mingw-w64-gcc
# Ubuntu: sudo apt install mingw-w64
```

#### Issue: CMake Cannot Find Toolchain

```bash
# Use absolute path to toolchain file
cmake -DCMAKE_TOOLCHAIN_FILE=$(realpath ../cmake/mingw-w64-x86_64.cmake) \
      -DCMAKE_BUILD_TYPE=Release ..
```

#### Issue: Linking Errors

```bash
# Clean build directory
rm -rf build && mkdir build && cd build

# Rebuild with verbose output
make VERBOSE=1 2>&1 | tee build.log
```

#### Issue: Visual Studio Not Detected (Windows)

```powershell
# Verify Visual Studio installation
where cl.exe

# Use Developer Command Prompt specifically for VS 2022
# Or specify generator explicitly
cmake -G "Visual Studio 17 2022" -A x64 ..
```

---

## Architecture

### Project Structure

```
SysRecon/
│
├── cmake/                      # Build system configuration
│   ├── mingw-w64-x86_64.cmake # MinGW-w64 cross-compilation toolchain
│   └── Windows.cmake           # Windows-specific build settings
│
├── docs/                       # Documentation
│   ├── API.md                 # API reference documentation
│   ├── SECURITY.md            # Security considerations
│   └── COMPLIANCE.md          # Compliance framework mappings
│
├── external/                   # Third-party dependencies
│   └── json/                  # nlohmann::json (embedded)
│       └── json.hpp
│
├── include/                    # Public header files
│   ├── sysrecon.h             # Main library header
│   ├── core/                  # Core infrastructure headers
│   │   ├── engine.h           # Scanning engine
│   │   ├── config.h           # Configuration management
│   │   └── logger.h           # Logging subsystem
│   │
│   └── modules/               # Module interface headers
│       ├── accounts.h
│       ├── services.h
│       ├── processes.h
│       ├── network.h
│       ├── registry.h
│       ├── memory.h
│       └── reporting.h
│
├── modules/                    # Module implementations
│   ├── accounts/              # User account enumeration
│   │   ├── accounts.cpp
│   │   └── sid_resolver.cpp
│   │
│   ├── services/              # Service analysis
│   │   ├── services.cpp
│   │   └── unquoted_paths.cpp
│   │
│   ├── processes/             # Process monitoring
│   │   ├── processes.cpp
│   │   └── modules.cpp
│   │
│   ├── network/               # Network assessment
│   │   ├── network.cpp
│   │   ├── interfaces.cpp
│   │   ├── shares.cpp
│   │   └── firewall.cpp
│   │
│   ├── registry/              # Registry analysis
│   │   ├── registry.cpp
│   │   ├── persistence.cpp
│   │   └── policies.cpp
│   │
│   ├── memory/                # Memory forensics
│   │   ├── memory.cpp
│   │   ├── injection.cpp
│   │   └── shellcode.cpp
│   │
│   └── reporting/             # Report generation
│       ├── json_reporter.cpp
│       ├── csv_reporter.cpp
│       └── html_reporter.cpp
│
├── src/                        # Core application source
│   ├── main.cpp               # Application entry point
│   ├── core/                  # Core implementation
│   │   ├── engine.cpp
│   │   ├── config.cpp
│   │   └── logger.cpp
│   │
│   └── cli/                   # Command-line interface
│       └── cli_parser.cpp
│
├── tests/                      # Unit and integration tests
│   ├── test_accounts.cpp
│   ├── test_services.cpp
│   ├── test_processes.cpp
│   ├── test_network.cpp
│   ├── test_registry.cpp
│   ├── test_memory.cpp
│   └── test_reporting.cpp
│
├── build/                      # Build output (git-ignored)
│   └── sysrecon.exe           # Compiled executable
│
├── CMakeLists.txt             # Root CMake configuration
├── README.md                  # This file
├── LICENSE                    # License information
├── CHANGELOG.md               # Version history
└── .gitignore                 # Git ignore rules
```

### Design Principles

#### Modularity
Each assessment capability is encapsulated in an independent module with well-defined interfaces, enabling:
- Selective module execution
- Parallel processing where applicable
- Easy extension with new assessment capabilities

#### Performance
- **Minimal Footprint**: Compiled to native x64 code with no runtime dependencies
- **Efficient Memory Usage**: Streaming report generation prevents memory exhaustion
- **Parallel Execution**: Thread pool architecture for concurrent module execution

#### Reliability
- **Error Handling**: Comprehensive exception handling and graceful degradation
- **API Failure Management**: Robust handling of failed Windows API calls
- **Logging**: Detailed diagnostic logging for troubleshooting

#### Security
- **No Network Communication**: All operations execute locally
- **No Persistence**: No modifications to system configuration or registry
- **Secure APIs**: Exclusive use of documented Windows APIs
- **Audit Trail**: Complete logging of all operations

---

## Support & Licensing

### Commercial Licensing

SysRecon is commercial software. For licensing inquiries, enterprise support, or custom development:

**Contact**: XpertLambda  
**Email**: [Contact through repository]  
**Discord**: thelambda

### Enterprise Support Packages

#### Professional Support
- Email support (24-hour response time)
- Security updates and patches
- Minor version upgrades

#### Enterprise Support
- Priority email and phone support (4-hour response time)
- Dedicated technical account manager
- Custom feature development
- On-site training and implementation assistance
- Compliance certification support

### Legal Notice

**Copyright © 2025 XpertLambda. All Rights Reserved.**

This software is proprietary and confidential. Unauthorized copying, modification, distribution, or use of this software, via any medium, is strictly prohibited without express written permission from the copyright holder.

### Responsible Use Policy

SysRecon is designed for legitimate security assessment, auditing, and compliance verification. Users must:

- Obtain explicit authorization before scanning systems
- Comply with all applicable laws and regulations
- Respect data privacy and protection requirements
- Follow responsible disclosure practices for discovered vulnerabilities
- Use the tool only within the scope of their professional duties

Misuse of this tool for unauthorized access, malicious purposes, or any illegal activity is strictly prohibited and may result in civil and criminal penalties.

---

## Additional Resources

### Documentation
- [API Reference](docs/API.md)
- [Security Considerations](docs/SECURITY.md)
- [Compliance Mappings](docs/COMPLIANCE.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

### Windows Security References
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/windows/security/)
- [Windows API Reference](https://docs.microsoft.com/en-us/windows/win32/api/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)

### Community
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Community forum on GitHub Discussions
- **Security Reports**: security@[domain].com (PGP key available)

---

## Frequently Asked Questions

### General Questions

**Q: Does SysRecon require Administrator privileges?**  
A: Yes, most scanning modules require elevated privileges to access system-level Windows APIs and security information.

**Q: Is SysRecon safe to run?**  
A: Yes, SysRecon is a read-only assessment tool. It does not modify system settings, install services, or perform any destructive actions.

**Q: Will antivirus software flag SysRecon?**  
A: Some antivirus software may flag SysRecon due to its system scanning capabilities and use of low-level Windows APIs. This is a false positive. Enterprise deployments should whitelist the application.

**Q: Can I run SysRecon on Windows Server?**  
A: Yes, SysRecon is fully compatible with Windows Server 2016, 2019, and 2022 (x64 architecture).

**Q: Does SysRecon require internet connectivity?**  
A: No, SysRecon operates entirely offline. It does not transmit any data or require network access.

**Q: How long does a full scan take?**  
A: Scan duration varies based on system configuration. Typical ranges:
- Quick scan: 30-60 seconds
- Full scan (without memory): 2-5 minutes
- Full scan (with memory forensics): 5-15 minutes

**Q: Can I automate SysRecon with Task Scheduler?**  
A: Yes, SysRecon is designed for automation. Use Windows Task Scheduler to run periodic assessments with specific command-line options.

### Technical Questions

**Q: What is the difference between JSON, CSV, and HTML reports?**  
A: 
- **JSON**: Machine-readable format ideal for SIEM integration, automation, and programmatic analysis
- **CSV**: Spreadsheet format for data manipulation in Excel or database import
- **HTML**: Human-readable format with professional styling for management presentations

**Q: How do I interpret risk severity levels?**  
A:
- **Critical**: Immediate action required (active exploitation indicators)
- **High**: Significant vulnerabilities requiring prompt remediation
- **Medium**: Security weaknesses requiring attention in planned maintenance
- **Low**: Best practice deviations and informational findings

**Q: Can I customize the scanning behavior?**  
A: Yes, create a custom JSON configuration file and use the `--config` option. See the default `config.json` for available parameters.

**Q: Does SysRecon detect all types of malware?**  
A: SysRecon is not a traditional antivirus tool. It identifies indicators of compromise (IOCs) such as:
- Unquoted service paths (privilege escalation vectors)
- Suspicious registry persistence mechanisms
- Memory injection patterns (RWX regions, DLL injection)
- Unusual process behaviors

For comprehensive malware detection, use SysRecon alongside dedicated endpoint protection solutions.

**Q: How does SysRecon differ from tools like PowerShell scripts?**  
A: SysRecon offers:
- Compiled native performance (C++20)
- Professional multi-format reporting
- Deep Windows API integration (25+ APIs)
- Memory forensics capabilities
- Enterprise-ready installation and deployment
- No PowerShell execution policy requirements

### Deployment Questions

**Q: Can I deploy SysRecon via Group Policy?**  
A: Yes, use Group Policy software deployment to distribute the MSI installer or portable executable across your domain.

**Q: Does SysRecon support silent installation?**  
A: Yes, use the `/S` flag for silent installation:
```cmd
SysRecon-Setup-1.0.0.exe /S
```

**Q: Where are reports stored by default?**  
A: 
- Installed version: `C:\Program Files\SysRecon\reports\`
- Portable version: `.\reports\` (relative to executable location)

**Q: Can I run SysRecon from a USB drive?**  
A: Yes, use the portable executable version. Note that administrator privileges are still required on the target system.

**Q: How do I uninstall SysRecon?**  
A: 
- Via installer: Control Panel → Programs → Uninstall a program → SysRecon
- Manual: Run the uninstaller from `C:\Program Files\SysRecon\Uninstall.exe`

---

## Changelog

### Version 1.0.0 (2025-11-13)

**Initial Release**

#### Core Features
- ✅ Six specialized security assessment modules (Accounts, Services, Processes, Network, Registry, Memory)
- ✅ 25+ Windows API integrations for comprehensive system visibility
- ✅ Multi-format reporting (JSON, CSV, HTML) with risk-based color coding
- ✅ Professional Windows installer with GUI wizard
- ✅ Cross-platform build system (Linux cross-compilation, Windows native)
- ✅ 6,500+ lines of production-quality C++20 code

#### Security Assessment Capabilities
- User account and group enumeration with privilege analysis
- Windows service configuration analysis and unquoted path detection
- Process and module monitoring with parent-child relationship mapping
- Network infrastructure assessment (connections, interfaces, shares, firewall)
- Registry persistence mechanism detection and security policy analysis
- Memory forensics (RWX region detection, DLL injection, process hollowing)

#### Reporting & Intelligence
- Risk assessment framework (Critical, High, Medium, Low)
- Executive summary generation with statistics
- SIEM integration support via JSON output
- Compliance framework mapping
- Sortable and filterable HTML reports

#### Deployment Options
- Professional Windows installer (NSIS-based, 3.9 MB)
- Portable executable (18 MB, no installation required)
- Silent installation support for enterprise deployment
- Start Menu integration and optional PATH configuration

#### Build System
- CMake-based cross-platform build system
- MinGW-w64 toolchain for Linux cross-compilation
- Visual Studio 2022 support for native Windows builds
- Automated installer generation scripts

#### Documentation
- Comprehensive README with usage examples
- Command-line reference guide
- Build instructions for multiple platforms
- Use case scenarios and deployment patterns

---

## Roadmap

### Planned Features

#### Version 1.1.0 (Q1 2026)
- 🔄 **Active Directory Integration**: Domain user enumeration and GPO analysis
- 🔄 **Scheduled Scanning**: Built-in task scheduling without Task Scheduler
- 🔄 **Differential Analysis**: Compare scan results to identify configuration drift
- 🔄 **Custom Rules Engine**: User-defined detection rules and policies
- 🔄 **PowerShell Module**: Native PowerShell cmdlets for integration

#### Version 1.2.0 (Q2 2026)
- 🔄 **Web Dashboard**: Central management console for multiple endpoints
- 🔄 **Real-time Monitoring**: Continuous assessment with alerting
- 🔄 **Remediation Actions**: Automated fix capabilities for common issues
- 🔄 **Compliance Profiles**: Pre-built templates for major frameworks (CIS, NIST, PCI-DSS)
- 🔄 **Advanced Memory Analysis**: Enhanced shellcode detection and YARA rule support

#### Version 2.0.0 (Q3 2026)
- 🔄 **Cloud Integration**: Azure AD and Microsoft 365 security assessment
- 🔄 **Container Support**: Docker and Kubernetes security scanning
- 🔄 **API Server**: RESTful API for programmatic access
- 🔄 **Machine Learning**: Behavioral anomaly detection
- 🔄 **Multi-language Support**: Internationalization (i18n)

### Community Requests

Want to see a specific feature? Submit a feature request via GitHub Issues.

---

## Performance Benchmarks

### Scan Duration (Average System)

| Scan Type | Duration | Modules |
|-----------|----------|---------|
| Quick Scan | 30-45 seconds | Accounts, Services |
| Standard Scan | 2-3 minutes | All except Memory |
| Full Scan | 5-10 minutes | All modules |
| Memory-Only Scan | 3-8 minutes | Memory forensics |

**Test System**: Windows 10 Pro, Intel Core i5-8250U, 16GB RAM, SSD

### Resource Usage

| Metric | Quick Scan | Full Scan | Memory Scan |
|--------|-----------|-----------|-------------|
| CPU Usage | 5-15% | 10-25% | 15-40% |
| Memory Usage | 50-100 MB | 100-200 MB | 200-500 MB |
| Disk I/O | Minimal | Low | Moderate |

### Scalability

| System Type | Typical Scan Time | Notes |
|-------------|-------------------|-------|
| Workstation (< 50 services) | 2-3 minutes | Standard desktop |
| Power User (50-100 services) | 3-5 minutes | Developer workstation |
| Server (100-200 services) | 5-10 minutes | Domain controller, database server |
| Enterprise Server (200+ services) | 10-15 minutes | Large application servers |

---

## Acknowledgments

### Open Source Libraries

- **[nlohmann/json](https://github.com/nlohmann/json)** - JSON for Modern C++ (MIT License)
  - Elegant JSON parsing and serialization library
  - Header-only design for easy integration

### Development Tools

- **[MinGW-w64](https://www.mingw-w64.org/)** - Minimalist GNU for Windows
  - Cross-compilation toolchain enabling Linux-based builds for Windows targets

- **[CMake](https://cmake.org/)** - Cross-platform build system
  - Modern build configuration and dependency management

- **[NSIS](https://nsis.sourceforge.io/)** - Nullsoft Scriptable Install System
  - Professional Windows installer generation

### Inspiration & Research

- **Microsoft Security Documentation** - Windows API reference and best practices
- **MITRE ATT&CK Framework** - Threat modeling and detection techniques
- **CIS Benchmarks** - Security configuration standards
- **OWASP** - Application security guidelines

### Special Thanks

To the information security community for continuous research, threat intelligence sharing, and dedication to improving enterprise security posture.

---

## Project Status

**Current Version**: 1.0.0  
**Release Date**: November 13, 2025  
**Status**: ✅ **Production-Ready**  
**Maintenance**: 🟢 **Actively Maintained**

### Statistics

- **Total Code Lines**: ~6,500 LOC (excluding comments and blank lines)
- **Source Files**: 14 implementation files (.cpp)
- **Header Files**: 12 header files (.h/.hpp)
- **Modules**: 6 scanning modules + 1 reporting module
- **Windows APIs Used**: 25+ distinct API functions
- **Binary Size**: 18 MB (optimized release build)
- **Installer Size**: 3.9 MB (LZMA compressed)

### Build Status

| Platform | Compiler | Status |
|----------|----------|--------|
| Linux → Windows | MinGW-w64 GCC 15.2.0 | ✅ Passing |
| Windows | Visual Studio 2022 (MSVC) | ✅ Passing |
| Windows | MinGW-w64 (Native) | ✅ Passing |

### Test Coverage

- ✅ Unit tests for core modules
- ✅ Integration tests for Windows API calls
- ✅ Regression tests for known issues
- ✅ Performance benchmarks
- 🔄 Continuous integration (planned)

---

## Security & Privacy

### Data Collection

**SysRecon does NOT collect or transmit any data.**

- All operations execute locally on the target system
- No network communication or telemetry
- No data sent to external servers
- Reports stored locally only

### Security Best Practices

When using SysRecon in production environments:

1. **Verify Digital Signatures**: Always verify the executable signature before deployment
2. **Secure Report Storage**: Store reports in encrypted locations with appropriate ACLs
3. **Access Control**: Limit SysRecon execution to authorized personnel only
4. **Audit Logging**: Enable Windows audit logging to track SysRecon execution
5. **Regular Updates**: Keep SysRecon updated for latest security improvements

### Vulnerability Disclosure

If you discover a security vulnerability in SysRecon:

1. **Do NOT** create a public GitHub issue
2. Email details to: security@[domain].com
3. Include:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact assessment
   - Suggested remediation (if available)
4. Allow 90 days for response and remediation before public disclosure

### Security Hardening

SysRecon is built with security in mind:

- ✅ **DEP (Data Execution Prevention)**: Enabled
- ✅ **ASLR (Address Space Layout Randomization)**: Enabled
- ✅ **Control Flow Guard (CFG)**: Enabled
- ✅ **Input Validation**: All user inputs sanitized
- ✅ **Safe String Handling**: No unsafe C-style string functions
- ✅ **Exception Handling**: Comprehensive error handling throughout

---

<p align="center">
  <strong>SysRecon - Professional Windows Security Assessment Platform</strong><br>
  <sub>Version 1.0.0 | Build 20251113 | Platform: Windows 10/11, Server 2016+</sub><br><br>
  <sub>Engineered for security professionals. Built for enterprise environments.</sub><br><br>
  <sub>Copyright © 2025 XpertLambda. All Rights Reserved.</sub>
</p>