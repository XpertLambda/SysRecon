# SysRecon - Windows Security Audit & Reconnaissance Tool

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/XpertLambda/SysRecon/releases)
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
- [Windows Hardening](#windows-hardening)
- [Build Instructions](#build-instructions)
- [Building the Installer](#building-the-installer)
- [Distribution](#distribution)
- [Architecture](#architecture)
- [Support & Licensing](#support--licensing)

---

## Overview

SysRecon is an enterprise-class security assessment platform designed to provide comprehensive visibility into Windows system configurations, security posture, and potential vulnerabilities. Built for security professionals, system administrators, and compliance teams, SysRecon automates the complex process of security auditing while delivering actionable intelligence through sophisticated analysis and reporting capabilities.

### Key Differentiators

- **Comprehensive Coverage**: Seven specialized assessment modules covering user accounts, services, processes, network infrastructure, registry configurations, memory forensics, and local privilege escalation
- **Actionable by Design**: Privilege-escalation findings carry a remediation step and a MITRE ATT&CK reference, turning raw audit output into a prioritized fix list
- **Enterprise Architecture**: Built with C++20 for optimal performance and minimal system footprint
- **Flexible Deployment**: Cross-platform compilation support with native Windows execution
- **Professional Reporting**: Multi-format output including JSON, CSV, and HTML with executive summaries and detailed technical findings
- **Tested**: about 8,500 lines of C++ with 94 unit tests and end-to-end CI on real Windows (Server 2022 and Windows 11)

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
- Detection of unquoted service paths-a critical privilege escalation vector
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
- Security policy review: User Account Control disabled (`EnableLUA = 0`)
- Registry permission and ACL analysis
- Image File Execution Options debugger hijacks
- Image File Execution Options (IFEO) monitoring for debugger attachments
- Run/RunOnce key enumeration across HKLM and HKCU hives

#### Memory Forensics & Analysis

- Injection detection: a PE image in private (non-file-backed) executable
  memory, the signature of a reflectively loaded module
- Process hollowing detection: the main image base backed by private rather
  than image memory
- Verified Windows system processes (name **and** path) are skipped

> **Current limitation:** the RWX-region check, the shellcode/malware scan and
> evidence dumps (`memory.create_dumps`) exist in the code but are not reached
> by any scan path in this version. See CHANGELOG "Known limitations".

#### Privilege Escalation Assessment

Read-only, host-local checks for the local privilege-escalation and
misconfiguration vectors a pen-tester checks first. Each finding includes a
remediation step and a MITRE ATT&CK reference, and the categories can be toggled
under `modules.privesc.*` in `config.json`.

- Unquoted service paths with a hijackable, writable prefix (T1574.009)
- Weak service DACLs granting reconfiguration rights to non-admins (T1543.003)
- World-writable service binaries / directories run as SYSTEM (T1574.010)
- `AlwaysInstallElevated` enabled in both HKLM and HKCU (T1548.002)
- Writable directories on `%PATH%` (binary/DLL planting) (T1574.007)
- Autorun targets writable by non-admins (T1547.001)
- Cleartext autologon credentials in the registry (T1552.002)
- UAC posture: `EnableLUA`, `LocalAccountTokenFilterPolicy` (T1548.002 / T1550.002)
- Leftover unattended-install answer files (T1552.001)

> SysRecon never exploits a finding or extracts a secret: credential checks
> report presence and location only.

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
| **Target OS** | Windows 10/11 and Windows Server 2016+ (x64). Tested in CI on Windows Server 2022 and Windows 11 |
| **Architecture** | x64 (64-bit) only |
| **Compiler** | MinGW-w64 GCC (cross-compilation, release builds) or MSVC 2022 (native; built and unit-tested in CI) |
| **Binary Format** | PE32+ executable (release binaries are not currently signed) |
| **Dependencies** | nlohmann/json 3.11.3 (header-only, embedded) |
| **Binary Size** | ~18 MB (optimized release build) |

### Windows API Integration

SysRecon leverages native Windows APIs for maximum compatibility and performance:

**Security & Identity**
- `NetUserEnum`, `NetUserModalsGet`, `NetLocalGroupEnum`, `NetLocalGroupGetMembers`
- `LookupAccountSid`, `LookupAccountName`, `CheckTokenMembership`
- `OpenProcessToken`, `AdjustTokenPrivileges`, `SetNamedSecurityInfo`

**Service Management**
- `OpenSCManager`, `EnumServicesStatusEx`, `QueryServiceConfig`, `QueryServiceStatus`

**Process & Memory**
- `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`
- `Module32First`, `Module32Next`, `QueryFullProcessImageName`
- `VirtualQueryEx`, `ReadProcessMemory`, `OpenProcess`

**Network Operations**
- `GetTcpTable2`, `GetExtendedUdpTable`, `GetAdaptersInfo`, `NetShareEnum`

**Registry Access**
- `RegOpenKeyEx`, `RegEnumValue`, `RegEnumKeyEx`
- `RegGetKeySecurity`, `RegQueryValueEx`

**System Information**
- `GetComputerName`, `RtlGetVersion`, `GetSystemInfo`, `IsWow64Process`

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
✅ **PATH Integration** - Optional (off by default) machine-PATH entry, removed again on uninstall  
✅ **Automatic Configuration** - Sets up reports directory and default config; an upgrade keeps your edited `config.json` (the shipped default stays in `configs\default.json`)  
✅ **Professional Uninstaller** - Complete removal with option to keep reports; `Uninstall.exe /S` runs fully unattended  

#### Quick Start:

1. Download `SysRecon-Setup-1.2.0.exe` from releases
2. Right-click → **"Run as Administrator"**
3. Follow the installation wizard
4. Launch from Start Menu → SysRecon

#### Building the Installer:

See the [Building the Installer](#building-the-installer) section below for complete documentation.

**Windows:**
```cmd
REM Install NSIS from: https://nsis.sourceforge.io/Download
REM Build the project first
build.bat

REM Create installer
build-installer.bat

REM Result: SysRecon-Setup-1.2.0.exe
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

# Result: SysRecon-Setup-1.2.0.exe (transfer to Windows)
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

### Interactive Menu Mode (Recommended for Beginners)

When you launch `sysrecon.exe` **without any arguments**, it will display an **interactive menu** that guides you through all available options:

```cmd
sysrecon.exe
```

**Interactive Menu Features:**
- 🎯 **User-Friendly Interface**: Navigate through options with simple number selections
- ✅ **Option Validation**: Menu input is range-checked and re-prompts on invalid entries
- 📋 **Module Selection**: Easily choose which security modules to run
- ⚙️ **Configuration**: Change settings without remembering command-line syntax
- 📊 **Report Options**: Select output formats visually
- 🔍 **Multiple Scan Modes**: Full scan, selective scan, quick scan, stealth mode

**Menu Options Include:**
1. Run Full System Scan (All Modules)
2. Run Selective Module Scan
3. Quick Scan Mode
4. Stealth Mode Scan
5. Configure Settings (output directory, formats, verbosity)
6. View Report Options
7. About / Version Info
8. Help & Command-Line Usage

**Example Workflow:**
```
1. Launch: sysrecon.exe
2. Choose option "2" (Selective Module Scan)
3. Select modules: 1 (Accounts), 2 (Services), 4 (Network)
4. Choose option "8" (Start Scan)
5. Reports generated automatically!
```

### Basic Operation

#### Full System Assessment

```cmd
sysrecon.exe
```

Launches the interactive menu. For command-line usage, see examples below.

To scan from the command line without the menu, pass any option. With no
module flag, the modules enabled in `config.json` run (everything except
Memory in the shipped config):

```cmd
sysrecon.exe --verbose
```

To include every module, Memory too:

```cmd
sysrecon.exe --all
```

**Configuration lookup.** Without `-c`, SysRecon uses `.\config.json` from the
working directory, then `config.json` next to `sysrecon.exe`. That second
location means an installed copy finds its config even from an elevated
prompt that starts in `C:\Windows\System32`. A relative `output_directory` in
the config is resolved against the config file's folder, so the installed
default writes to `C:\Program Files\SysRecon\reports`. If no config is found,
built-in defaults apply, and they also keep Memory off. A config file that
exists but is invalid (bad JSON, wrong value types, failed validation) stops
the run with the specific errors listed. Unknown or removed settings are
reported as warnings.

#### Quick Assessment Mode

```cmd
sysrecon.exe --quick
```

Runs the essential checks only: local users, services, listening ports,
firewall state and Run keys. Processes and Memory are skipped.

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

REM Local privilege-escalation assessment
sysrecon.exe --privesc
```

A module flag **replaces** the config file's module selection, so
`sysrecon.exe --memory` runs the Memory module even though the shipped config
disables it. Before this fix, a module disabled in the config could not be
turned back on from the command line.

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

REM All formats
sysrecon.exe --format all
```

Without `--format`, the `output.generate_json` / `generate_csv` /
`generate_html` settings in `config.json` decide (all three by default).

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

Low-footprint mode for production hosts. Concretely, stealth mode:

- turns off console logging (the log file and reports are still written);
- skips the per-process loaded-DLL snapshots, which open a handle to every
  process;
- never runs the Memory module, even when it is requested with `--memory` or
  `--all`.

It does not hide SysRecon from EDR and makes no attempt to; it only leaves out
the checks that touch other processes. `general.stealth_mode` in `config.json`
turns it on as well.

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
| `--quick` | Essential checks only (users, services, listening ports, firewall, Run keys) |
| `--stealth` | Low-footprint scan: no console log, no per-process DLL snapshots, no Memory module |

### Configuration Options

| Option | Argument | Description |
|--------|----------|-------------|
| `-c, --config` | `<file>` | Load configuration from a JSON file. Default: `.\config.json`, then `config.json` next to `sysrecon.exe`. A missing or invalid explicit file is an error |
| `-o, --output` | `<directory>` | Output directory (default: the config's `output_directory`, resolved against the config file's folder) |
| `-f, --format` | `<format>` | Report format: `json`, `csv`, `html`, `all` (default: the config's `generate_*` settings) |

### Module Selection

| Option | Module | Scope |
|--------|--------|-------|
| `--accounts` | User Accounts | Local user enumeration, group analysis, privilege assessment |
| `--services` | Windows Services | Service configuration, startup analysis, path validation |
| `--processes` | Running Processes | Process enumeration, module loading, memory footprint |
| `--network` | Network Infrastructure | Connections, interfaces, shares, firewall rules |
| `--registry` | Registry Analysis | Persistence keys, security policies, ACL analysis |
| `--memory` | Memory Forensics | Injection and process-hollowing detection (see the limitation note under Memory Forensics) |
| `--all` | All Modules | All six modules, including Memory |

Without any module flag, the modules enabled in `config.json` run. With one or
more flags, exactly those modules run, whatever the config says.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed and every requested report was written. Checks that could not complete are listed under **Incomplete Checks** in each report |
| `1` | Invalid arguments, missing or invalid config file, no modules selected, initialization failure (including `require_admin` without elevation), or a report that could not be written |

### Advanced Options

Administrator enforcement is controlled by `general.require_admin` in
`config.json` rather than a command-line flag. It is applied only when a
configuration file is actually loaded.

> **Note:** SysRecon executes its modules sequentially and does not enforce
> per-module timeouts. Earlier documentation described `--threads` and
> `--timeout` options; no such options existed, and the corresponding
> `max_threads` / `timeout_seconds` settings have been removed from
> `config.json` rather than left as settings that do nothing. See the Roadmap.

---

## Output & Reporting

### Report Formats

#### JSON Output

**Purpose**: Machine-readable structured data for SIEM integration, API consumption, and automated analysis workflows.

**Structure** (abridged from a real report; findings are sorted by severity):
```json
{
  "scan_info": {
    "version": "1.2.0",
    "timestamp": "20261101_212458",
    "hostname": "WORKSTATION-01",
    "os_version": "Windows 11 (Build 22631)",
    "current_user": "analyst",
    "elevated": true,
    "stealth_mode": false,
    "config": "C:\\Program Files\\SysRecon\\config.json",
    "modules": ["Accounts", "Services", "Processes", "Network", "Registry"],
    "total_findings": 37
  },
  "system_info": {
    "computer_name": "WORKSTATION-01",
    "os_version": "Windows 11 (Build 22631)",
    "architecture": "x64"
  },
  "results": [
    {
      "module": "Account Policy",
      "item": "Minimum password length",
      "description": "Minimum password length is below the CIS baseline",
      "risk_level": "Medium",
      "details": {
        "Current": "7",
        "Recommended (CIS L1)": ">= 14",
        "Remediation": "Invoke-SysReconHardening.ps1 -Include AccountPolicy",
        "Technique": "T1110 Brute Force"
      }
    }
  ],
  "summary": { "critical": 0, "high": 3, "medium": 9, "low": 25, "total": 37 },
  "incomplete_checks": []
}
```

`incomplete_checks` lists every check that failed or could not run (for
example without Administrator rights). An empty array means every selected
check completed.

#### CSV Output

**Purpose**: Spreadsheet analysis, database import, and business intelligence tools.

**Structure**: UTF-8 with BOM; every field quoted per RFC 4180 and protected
against spreadsheet formula injection. Details are joined as `key: value; ...`.
Incomplete checks appear as extra rows with module `SysRecon`.
```csv
Module,Item,Risk Level,Description,Details
"Account Policy","Minimum password length","Medium","Minimum password length is below the CIS baseline","Current: 7; Recommended (CIS L1): >= 14; ..."
"Services","BackupService","High","Service: BackupService","Binary Path: C:\Program Files\Backup\svc.exe; Unquoted Path: Yes - Potential binary hijacking risk; ..."
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

## Windows Hardening

SysRecon audits; it does not change the system. To **act** on what it finds,
the project ships a separate, opt-in hardening script that applies a **CIS
Level 1 (workstation)-aligned** baseline:

```
hardening/Invoke-SysReconHardening.ps1
```

`sysrecon.exe` stays strictly read-only. This PowerShell script is the *only*
component that writes to the OS - it is deliberately separate and elevated so
the audit tool keeps its read-only guarantee.

### The closed loop

```powershell
sysrecon.exe                              # 1. audit  -> findings
.\hardening\Invoke-SysReconHardening.ps1  # 2. PREVIEW the fixes (changes nothing)
.\hardening\Invoke-SysReconHardening.ps1 -Apply   # 3. back up, then remediate
sysrecon.exe                              # 4. re-audit -> confirm findings cleared
```

### Safe on fresh *and* already-used installs

The script is built around four guarantees, not bolt-ons:

- **Preview by default.** Nothing changes without `-Apply`. The default run
  prints the exact `current -> desired` change set and touches nothing.
- **Reversible.** Before the first change it writes a timestamped backup bundle
  (registry exports, `secedit`/`auditpol`/firewall exports) and attempts a
  System Restore point. Undo with `-Rollback <bundle>`.
- **Idempotent.** Each control writes only on drift; a second `-Apply` on a
  hardened host reports zero changes.
- **Scoped.** `-Level 1` (default) is designed not to break normal use.
  `-Level 2` and destructive controls (`-EnableBitLocker`, `-DisableRDP`,
  `-EnableCredentialGuard`) are opt-in behind explicit switches.

### What it covers

Windows Firewall · SMBv1 removal and SMB signing · UAC · legacy-auth hardening
(NTLMv2-only, WDigest, LLMNR/NBT-NS, anonymous access) · password & lockout
policy · Guest account · Microsoft Defender and 15 Attack Surface Reduction
rules · AutoRun/AutoPlay · advanced audit policy (incl. process-creation
command line) · PowerShell logging · LSA protection · interactive-logon
lockdown · RDP hardening. See **[docs/HARDENING.md](docs/HARDENING.md)** for the
full control catalogue with CIS references, per-control breakage notes, the
rollback runbook, and the VM validation checklist.

> **Honest scope.** This is a pragmatic scripted subset of CIS L1 for a
> standalone workstation - not a replacement for full CIS-CAT tooling or the
> Microsoft Security Baseline GPOs, and it does not claim to secure
> "everything." It has been syntax- and lint-checked and its logic unit-tested,
> but **not yet run end-to-end on a live Windows host by us**; validate on a VM
> (fresh + used snapshots) before production use.

---

## Build Instructions

> **📘 Build Guide**: The sections below cover Linux cross-compilation, Windows
> native builds, NSIS installer creation, distribution packaging, and
> troubleshooting.

### Quick Start: Building on Linux

#### Prerequisites Setup

**Arch Linux:**
```bash
sudo pacman -S mingw-w64-gcc cmake make git
```

**Ubuntu 20.04 LTS / Debian 11:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y mingw-w64 cmake build-essential git
```

**Fedora 35+ / RHEL 8:**
```bash
sudo dnf install -y mingw64-gcc-c++ cmake make git
```

#### Simple Build Process

```bash
# Clone repository
git clone https://github.com/XpertLambda/SysRecon.git
cd SysRecon

# Run build script (easiest method)
./build.sh

# Output: build/sysrecon.exe (~17 MB)
```

#### Manual Build (Advanced)

```bash
# Create build directory
mkdir -p build && cd build

# Configure with MinGW-w64 toolchain
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      ..

# Build with parallel compilation
make -j$(nproc)

# Output: build/sysrecon.exe
```

### Building on Windows (Native)

#### Prerequisites Setup

1. **Install Visual Studio 2022**
   - Download Community Edition from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/)
   - Select **"Desktop development with C++"** workload
   - Include Windows 10/11 SDK

2. **Install CMake & Git**
   - CMake: [cmake.org/download](https://cmake.org/download/)
   - Git: [git-scm.com](https://git-scm.com/download/win)

#### Build Process

```powershell
# Open "Developer Command Prompt for VS 2022"

# Clone repository
git clone https://github.com/XpertLambda/SysRecon.git
cd SysRecon

# Run build script
.\build.bat

# Or manual build:
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release --parallel

# Output: build\Release\sysrecon.exe
```

---

## Building the Installer

### Prerequisites

**Install NSIS (Nullsoft Scriptable Install System):**

```bash
# Arch Linux (using AUR helper)
yay -S nsis
# or
paru -S nsis

# Ubuntu/Debian
sudo apt install nsis

# Fedora/RHEL
sudo dnf install nsis

# Verify installation
makensis -VERSION  # Should show v3.11 or higher
```

### Create Windows Installer

```bash
# 1. Build the executable first
./build.sh

# 2. Run installer build script
./build-installer.sh

# Output: SysRecon-Setup-1.2.0.exe (~3.9 MB)
```

**What the installer includes:**
- ✅ Main executable (sysrecon.exe)
- ✅ Default configuration (config.json)
- ✅ Documentation (README.txt)
- ✅ License file
- ✅ Start Menu shortcuts (6 shortcuts)
- ✅ Optional desktop shortcut
- ✅ Uninstaller
- ✅ Registry integration

---

## Distribution

### What to Distribute

**Option 1: Windows Installer (Recommended) ⭐**
```
📦 SysRecon-Setup-1.2.0.exe  (3.9 MB)
   - Complete installation package
   - Professional setup wizard
   - Easy uninstallation
```

**Option 2: Portable Package**
```
📦 SysRecon-1.2.0-Portable.zip  (~17 MB)
   ├── sysrecon.exe          # Main executable
   ├── config.json           # Configuration
   ├── README.md             # Documentation
   ├── LICENSE               # License file
   └── reports/              # Output folder
```

**Option 3: Both (Complete Distribution)**
```
Upload to GitHub Release:
   ├── SysRecon-Setup-1.2.0.exe    # Installer
   ├── sysrecon.exe                # Portable executable
   ├── checksums.txt               # SHA256 hashes
   └── Source code (auto-generated by GitHub)
```

### Create Checksums

```bash
# Generate SHA256 checksums for verification
sha256sum SysRecon-Setup-1.2.0.exe > checksums.txt
sha256sum build/sysrecon.exe >> checksums.txt

# Users can verify integrity on Windows:
# Get-FileHash -Algorithm SHA256 SysRecon-Setup-1.2.0.exe
```

### Required Files Summary

**Minimum (Portable):**
- `sysrecon.exe` (main executable)
- `config.json` (configuration file)

**Recommended (Complete):**
- `SysRecon-Setup-1.2.0.exe` (installer - includes everything)
- `checksums.txt` (file verification)
- Documentation (README, CHANGELOG)

---

## Build Troubleshooting

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
│   └── version.h.in           # Version header template
│
├── docs/                       # Documentation
│   └── HARDENING.md           # Windows hardening control catalogue
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
│   │   ├── logger.h           # Logging subsystem
│   │   ├── text_utils.h       # Text/encoding helpers
│   │   ├── utils.h            # Shared utilities
│   │   └── whitelist.h        # Whitelist matching
│   │
│   └── modules/               # Module interface headers
│       ├── accounts/user_enum.h
│       ├── services/service_enum.h
│       ├── processes/process_enum.h
│       ├── network/network_enum.h
│       ├── registry/registry_analyzer.h
│       ├── memory/memory_analyzer.h
│       └── reporting/report_generator.h
│
├── modules/                    # Module implementations
│   ├── accounts/user_enum.cpp         # User account enumeration
│   ├── services/service_enum.cpp      # Service analysis
│   ├── processes/process_enum.cpp     # Process monitoring
│   ├── network/network_enum.cpp       # Network assessment
│   ├── registry/registry_analyzer.cpp # Registry analysis
│   ├── memory/memory_analyzer.cpp     # Memory forensics
│   └── reporting/report_generator.cpp # Report generation
│
├── src/                        # Core application source
│   ├── main.cpp               # Application entry point
│   └── core/                  # Core implementation
│       ├── engine.cpp         # Scan lifecycle (Windows)
│       ├── utils.cpp          # Win32 helpers (Windows)
│       ├── config.cpp         # ┐
│       ├── logger.cpp         # │
│       ├── scan_plan.cpp      # │ sysrecon_core: portable,
│       ├── text_utils.cpp     # │ unit-tested natively
│       └── utils_common.cpp   # ┘
│
├── tests/                      # Unit and regression tests (sysrecon_core)
│   ├── test_core.cpp           # Utils, UTF-8 codec, Logger
│   ├── test_config.cpp         # config.json parsing and validation
│   ├── test_scan_plan.cpp      # Module/format/config-path precedence
│   ├── test_text_utils.cpp     # IPv4, registry buffers, file names
│   ├── test_report_escaping.cpp
│   └── test_whitelist.cpp
│
├── hardening/                  # Opt-in Windows hardening companion
│   ├── Invoke-SysReconHardening.ps1
│   └── PSScriptAnalyzerSettings.psd1
│
├── build/                      # Build output (git-ignored)
│   └── sysrecon.exe           # Compiled executable
│
├── CMakeLists.txt             # Root CMake configuration
├── installer.nsi              # NSIS installer script
├── README.md                  # This file
├── LICENSE                    # License information
├── CHANGELOG.md               # Version history
└── .gitignore                 # Git ignore rules
```

### Design Principles

#### Modularity
Each assessment capability is encapsulated in an independent module with well-defined interfaces, enabling:
- Selective module execution
- Easy extension with new assessment capabilities

#### Performance
- **Minimal Footprint**: Compiled to native x64 code with no runtime dependencies
- **Sequential Execution**: Modules run one after another. There is no thread
  pool and no concurrency; a slow module (for example memory analysis on a busy
  host) extends the total scan time. Parallel execution is on the roadmap.

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
- [Windows Hardening Guide](docs/HARDENING.md)
- [Changelog](CHANGELOG.md)

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
A: Yes. `sysrecon.exe` is a read-only assessment tool - it does not modify system settings, install services, or perform any destructive actions. The only component that writes to the system is the separate, opt-in `hardening/Invoke-SysReconHardening.ps1` script, which you must run explicitly and elevated, previews changes by default, and backs up before applying. See [Windows Hardening](#windows-hardening).

**Q: Will antivirus software flag SysRecon?**  
A: Some antivirus software may flag SysRecon due to its system scanning capabilities and use of low-level Windows APIs. This is a false positive. Enterprise deployments should whitelist the application.

**Q: Can I run SysRecon on Windows Server?**  
A: Yes. CI runs the full install-scan-uninstall test on Windows Server 2022 (and on Windows 11). Server 2016 and 2019 use the same APIs and are expected to work, but are not tested.

**Q: Does SysRecon require internet connectivity?**  
A: No, SysRecon operates entirely offline. It does not transmit any data or require network access.

**Q: How long does a full scan take?**  
A: It depends on the host, mainly on the number of processes and services. The quick scan and a scan without the memory module usually take seconds; the memory module takes much longer because it walks other processes' address spaces. Every run prints its duration (`[+] Scan completed in ...`), so measure on your own estate.

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
- Memory injection patterns (reflectively loaded PE images, process hollowing)
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
A: There is no MSI package. Deploy the NSIS installer silently (below) with a startup script, Intune or another software-distribution tool, or copy the portable executable and `config.json` together.

**Q: Does SysRecon support silent installation?**  
A: Yes. `/S` installs silently with the default components; add `/ADDTOPATH`
to also add the install directory to the machine PATH. `/S` on the
uninstaller removes it silently and keeps generated reports:
```cmd
SysRecon-Setup-1.2.0.exe /S
SysRecon-Setup-1.2.0.exe /S /ADDTOPATH
"C:\Program Files\SysRecon\Uninstall.exe" /S
```
An upgrade (`/S` over an existing install) keeps your edited `config.json`.

**Q: Where are reports stored by default?**  
A: 
- Installed version: `C:\Program Files\SysRecon\reports\`
- Portable version: `reports\` next to `config.json`, so next to the executable when the two are kept together; `.\reports\` in the working directory if no config file is found

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
- Memory forensics (reflectively loaded PE images, process hollowing)

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

### Deferred from 1.1.0

These were previously present as configuration settings or declared API that the
binary did not implement. They have been removed rather than left in place doing
nothing, and are listed here as genuine future work:

- 🔄 **Report encryption and signing**: `encrypt_output` / `sign_reports`
  previously produced an unencrypted, unsigned report with no warning.
- 🔄 **Parallel module execution and per-module timeouts**: `max_threads` /
  `timeout_seconds` had no implementation behind them.
- 🔄 **PDF / XML / plain-text reports**: JSON, CSV and HTML are supported.
- 🔄 **Report compression**: `compress_output` was ignored.
- 🔄 **Signed release binaries** and published checksums.

### Planned Features

#### Next release
- 🔄 **Differential Analysis**: Compare scan results to identify configuration
  drift - the single highest-value addition for separating signal from noise
- 🔄 **Active Directory Integration**: Domain user enumeration and GPO analysis
- 🔄 **Scheduled Scanning**: Built-in task scheduling without Task Scheduler
- 🔄 **Custom Rules Engine**: User-defined detection rules and policies
- 🔄 **PowerShell Module**: Native PowerShell cmdlets for integration

#### Later
- 🔄 **Web Dashboard**: Central management console for multiple endpoints
- 🔄 **Real-time Monitoring**: Continuous assessment with alerting
- 🟡 **Remediation Actions**: A CIS L1 hardening script ships now (see [Windows Hardening](#windows-hardening)); in-tool automated remediation driven directly by findings remains future work.
- 🟡 **Compliance Profiles**: CIS L1 (workstation) is implemented in the hardening script; NIST and PCI-DSS profiles remain future work.
- 🔄 **Advanced Memory Analysis**: Enhanced shellcode detection and YARA rule support

#### Longer term
- 🔄 **Cloud Integration**: Azure AD and Microsoft 365 security assessment
- 🔄 **Container Support**: Docker and Kubernetes security scanning
- 🔄 **API Server**: RESTful API for programmatic access
- 🔄 **Machine Learning**: Behavioral anomaly detection
- 🔄 **Multi-language Support**: Internationalization (i18n)

### Community Requests

Want to see a specific feature? Submit a feature request via GitHub Issues.

---

## Performance

> **These are rough expectations, not measured benchmarks.** SysRecon has no
> benchmark suite; scan time depends heavily on the number of services and
> processes on the host, and on whether the memory module is enabled. Treat the
> figures below as order-of-magnitude guidance and measure on your own estate.

### Scan Scope

| Scan Type | Modules |
|-----------|---------|
| Quick Scan (`--quick`) | Accounts (users), Services, Network (listening ports, firewall), Registry (startup keys) |
| Full Scan (default) | All enabled modules, subject to `config.json` |
| Memory | Disabled by default - see Operational Considerations before enabling |

Modules run sequentially, so total scan time is the sum of the enabled modules.
Memory analysis dominates when enabled, because it walks the address space of
every non-whitelisted process.

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

**Current Version**: 1.2.0  
**Release Date**: November 1, 2026  
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
| Linux → Windows | MinGW-w64 GCC | ✅ Passing (verified in CI on every push) |
| Windows | Visual Studio 2022 (MSVC) | ⚠️ Not verified - not covered by CI |
| Windows | MinGW-w64 (Native) | ⚠️ Not verified - not covered by CI |

### Test Coverage

- ✅ Continuous integration (GitHub Actions): native unit tests, Windows
  cross-compile, and a wine smoke test on every push and pull request
- ✅ Unit tests (94) for the platform-independent core (`sysrecon_core`):
  report escaping (HTML/CSV), whitelist matching, path handling, IPv4 parsing,
  UTF-8 conversion, `Utils`, `Logger`, `config.json` parsing and validation
  (including the shipped file), module/format/config-path precedence, registry
  buffer decoding and file-name sanitising
- ✅ Regression tests pinning known security issues: report XSS, CSV formula
  injection, whitelist evasion via masquerading, and loss of redirected output
- ✅ CI also builds the NSIS installer (`makensis -WX`), checks that
  interactive mode exits on end of input, and lints the hardening script with
  PSScriptAnalyzer on a Windows runner
- ✅ End-to-end Windows test on a GitHub `windows-latest` runner
  (`tests/windows/smoke-test.ps1`): silent install with `/ADDTOPATH`, scans that
  must complete with no incomplete checks, config discovery, report formats,
  stealth and error handling, upgrade keeping `config.json`, and a silent
  uninstall under a timeout. The script also runs by hand in a disposable VM
- 🔄 Integration tests against live Windows APIs - currently manual, on a
  Windows VM; see the Verification section of the delivery plan
- ❌ Performance benchmarks - not implemented

Run the suite with:

```bash
cmake -S . -B build-tests -DSYSRECON_BUILD_TESTS=ON -DSYSRECON_WERROR=ON
cmake --build build-tests --target sysrecon_tests -j$(nproc)
cd build-tests && ctest --output-on-failure
```

---

## Security & Privacy

### Data Collection

**SysRecon does NOT collect or transmit any data.**

- All operations execute locally on the target system
- No network communication or telemetry
- No data sent to external servers
- Reports stored locally only

### Operational Considerations

Read this before running SysRecon on a production or monitored host.

- **It will likely trigger EDR.** The memory module opens other processes with
  `PROCESS_VM_READ` and walks their address space - including `lsass.exe`. That
  is the canonical credential-dumping signature, and the binary also links
  `dbghelp` and can call `MiniDumpWriteDump`. Expect alerts, and coordinate with
  your security team before running it. Disable the memory module
  (`modules.memory.enabled: false`, the default) if you do not need it.
- **Reports are sensitive.** They contain usernames, SIDs, administrator group
  membership, full service paths, listening ports, and network interface
  MAC/IP addresses. Each report and log file gets a protected ACL granting
  access only to SYSTEM, Administrators and the file's owner, so a non-admin
  colleague needs a copy. They are not encrypted or signed - SysRecon does not
  implement at-rest encryption. Store and transfer them accordingly.
- **Where output goes.** A relative `output_directory` in `config.json` is
  resolved against the config file's folder, and the config is also looked up
  next to `sysrecon.exe`, so an installed copy writes to its own `reports`
  folder whatever the working directory. A relative `-o` is relative to the
  working directory. With no config file at all, the default is `./reports`
  in the working directory.
- **Administrator rights are required for complete results.** Without them,
  process image paths, service configuration and memory inspection are partly
  or wholly unavailable, and SysRecon reports which checks did not complete
  rather than silently returning a clean result.
- **Findings are leads, not verdicts.** Detections such as "runs from a
  user-writable location" legitimately match installers and updaters. Confirm
  before acting.

### Security Best Practices

When using SysRecon in production environments:

1. **Verify the Binary**: Check the published SHA256 of the release you
   downloaded. Note that release binaries are not currently Authenticode-signed,
   so SmartScreen and some EDR products will flag them.
2. **Secure Report Storage**: Move reports to a location with restricted ACLs;
   SysRecon does not encrypt them (see Operational Considerations above).
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

- ✅ **DEP (NX compatible)** and **ASLR (dynamic base, high-entropy VA)**: set
  in the PE header of release builds and checked by CI on every build
- ❌ **Control Flow Guard**: not enabled; the MinGW-w64 GCC toolchain used for
  release builds does not emit CFG metadata
- ✅ **Report output is inert**: every host-derived value is HTML-escaped and
  CSV values are protected against formula injection (unit-tested)
- ✅ **Reports and logs are access-restricted**: a protected ACL limits them to
  SYSTEM, Administrators and the file's owner
- ✅ **Untrusted data is bounds-checked**: registry strings, process memory
  headers and config values are validated before use (unit-tested)

---

<p align="center">
  <strong>SysRecon - Professional Windows Security Assessment Platform</strong><br>
  <sub>Version 1.2.0 | Platform: Windows 10/11, Server 2016+</sub><br><br>
  <sub>Engineered for security professionals. Built for enterprise environments.</sub><br><br>
  <sub>Copyright © 2025 XpertLambda. All Rights Reserved.</sub>
</p>