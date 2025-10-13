# SysRecon User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Line Reference](#command-line-reference)
5. [Configuration](#configuration)
6. [Understanding Reports](#understanding-reports)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

## Introduction

SysRecon is a professional Windows security auditing tool designed to help IT administrators, security professionals, and penetration testers assess the security posture of Windows systems. It performs comprehensive analysis of system configurations, user accounts, services, network settings, registry entries, and memory to identify potential security risks and misconfigurations.

### Key Features
- **Comprehensive System Analysis**: Deep inspection of all critical system components
- **Risk Assessment**: Automated risk scoring with clear severity levels
- **Multiple Report Formats**: JSON, CSV, HTML, and PDF outputs
- **Stealth Operation**: Minimal system footprint for covert assessments
- **Enterprise Ready**: Designed for large-scale deployment scenarios

## Installation

### System Requirements
- **Operating System**: Windows 10/11, Windows Server 2016/2019/2022
- **Architecture**: x64 (64-bit)
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 100MB free space
- **Privileges**: Administrator rights recommended for full functionality

### Installation Steps

1. **Download the latest release** from the official repository
2. **Extract the ZIP file** to your preferred location (e.g., `C:\Tools\SysRecon`)
3. **Verify the executable** is present: `sysrecon.exe`
4. **Run a test scan** to ensure proper installation

```cmd
cd C:\Tools\SysRecon
sysrecon.exe --help
```

### Running Without Administrator Privileges
While SysRecon can run without administrator privileges, some features will be limited:
- Process memory analysis
- Service configuration details
- Registry security settings
- System-level user account information

## Quick Start

### Basic Scan
Perform a standard security assessment with default settings:

```cmd
sysrecon.exe
```

This will:
- Scan all enabled modules
- Generate an HTML report
- Save results to `./reports` directory

### Quick Assessment
For a rapid security overview:

```cmd
sysrecon.exe --quick --format json
```

### Custom Output Location
Specify where to save reports:

```cmd
sysrecon.exe --output "C:\SecurityReports"
```

### Specific Module Scan
Focus on particular areas:

```cmd
# User accounts and services only
sysrecon.exe --accounts --services

# Network security assessment
sysrecon.exe --network --registry --format html
```

## Command Line Reference

### General Options
```
-h, --help              Show help message and exit
-v, --version           Display version information
-c, --config FILE       Load configuration from JSON file
-o, --output DIR        Set output directory for reports
-f, --format FORMAT     Report format: json, csv, html, pdf, all
-q, --quick             Run quick scan (essential checks only)
-s, --stealth           Enable stealth mode (minimal output)
--verbose               Enable detailed logging
--no-admin              Skip administrator privilege check
```

### Module Selection
```
--accounts              Enable user account enumeration
--services              Enable service analysis
--processes             Enable process monitoring
--network               Enable network assessment
--registry              Enable registry analysis
--memory                Enable memory forensics
--all                   Enable all modules (default)
```

### Example Commands

**Complete Security Audit**
```cmd
sysrecon.exe --format all --output "C:\Audit\Results"
```

**Stealth Reconnaissance**
```cmd
sysrecon.exe --stealth --quick --accounts --network
```

**Memory Forensics Focus**
```cmd
sysrecon.exe --memory --processes --verbose
```

**Custom Configuration**
```cmd
sysrecon.exe --config custom_scan.json --format html
```

## Configuration

### Configuration File Format
Create a `config.json` file to customize scan behavior:

```json
{
    "general": {
        "verbose_output": false,
        "stealth_mode": false,
        "max_threads": 4,
        "timeout_seconds": 300
    },
    "modules": {
        "accounts": {
            "enabled": true,
            "enumerate_groups": true,
            "analyze_permissions": true,
            "check_passwords": false
        },
        "services": {
            "enabled": true,
            "analyze_startup": true,
            "check_dependencies": true,
            "verify_signatures": false
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
            "custom_keys": [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ]
        },
        "memory": {
            "enabled": false,
            "create_dumps": false,
            "scan_for_malware": true,
            "max_dump_size_mb": 100
        }
    },
    "output": {
        "output_directory": "./reports",
        "generate_json": true,
        "generate_html": true,
        "compress_output": true
    },
    "security": {
        "encrypt_output": false,
        "sign_reports": false
    }
}
```

### Performance Tuning
- **max_threads**: Adjust based on system CPU cores
- **timeout_seconds**: Increase for slow systems or comprehensive scans
- **stealth_mode**: Enable for minimal system impact

## Understanding Reports

### Risk Levels
- **🔴 Critical**: Immediate security threats requiring urgent action
- **🟠 High**: Significant risks that should be addressed promptly
- **🟡 Medium**: Moderate risks for next maintenance window
- **🟢 Low**: Minor issues and informational findings

### Common Findings

#### User Account Issues
- Disabled built-in Administrator account (Good)
- Users with password never expires (Medium)
- Unused accounts with high privileges (High)
- Guest account enabled (High)

#### Service Vulnerabilities
- Unquoted service paths (Medium to High)
- Services running as SYSTEM unnecessarily (Medium)
- Unsigned service executables (Medium)
- Suspicious service locations (High)

#### Network Security
- Unnecessary open ports (Medium)
- Services listening on all interfaces (Medium)
- Suspicious network connections (High)
- Weak firewall configuration (High)

#### Registry Concerns
- Suspicious startup entries (High)
- Unsigned executables in Run keys (Medium)
- Weak security policies (Medium to High)
- Unauthorized modifications (Critical)

### Report Formats

#### HTML Report
- Interactive dashboard view
- Risk summaries with charts
- Detailed findings with recommendations
- Searchable and filterable results

#### JSON Report
- Machine-readable format
- Complete raw data
- Suitable for automation and SIEM integration
- Preserves all metadata

#### CSV Report
- Spreadsheet-compatible format
- Good for analysis and sorting
- Easy to import into other tools
- Simplified view of findings

## Troubleshooting

### Common Issues

**"Access Denied" Errors**
- Solution: Run as Administrator
- Alternative: Use `--no-admin` flag with limited functionality

**Antivirus Detection**
- Solution: Add SysRecon to AV exclusions
- Note: This is expected behavior for security tools

**Slow Performance**
- Solution: Reduce thread count in configuration
- Alternative: Use `--quick` mode for faster scans

**Missing Modules in Report**
- Check: Module may be disabled in configuration
- Fix: Enable specific modules with command line flags

**Network Connectivity Issues**
- Firewall may be blocking hostname resolution
- Use `resolve_hostnames: false` in configuration

### Logging and Debugging

Enable verbose logging:
```cmd
sysrecon.exe --verbose --output "C:\Debug"
```

Check log files in the output directory for detailed error information.

### Getting Help

1. Check this user manual
2. Review the troubleshooting section
3. Examine log files for specific errors
4. Contact support with log files and system information

## Best Practices

### Regular Assessments
- Run monthly security scans
- Compare results over time
- Track remediation progress
- Document baseline configurations

### Enterprise Deployment
- Use configuration files for consistency
- Centralize report collection
- Integrate with existing security tools
- Establish scanning schedules

### Security Considerations
- Store reports securely
- Use encryption for sensitive environments
- Limit access to scanning tools
- Follow responsible disclosure practices

### Performance Optimization
- Schedule scans during maintenance windows
- Use stealth mode on production systems
- Monitor system resources during scans
- Adjust thread counts based on system load

### Report Management
- Archive reports for compliance
- Create executive summaries for management
- Track remediation efforts
- Use reports for security metrics
