# SysRecon Quick Start Examples

## 🚀 Basic Usage Examples

### 1. Simple Security Scan
```bash
# Basic scan with default settings
./sysrecon.exe

# Output: Creates reports in ./reports/ directory
```

### 2. Comprehensive Security Audit
```bash
# Full audit with all modules enabled
./sysrecon.exe --full --output C:\SecurityAudit\ --format all

# Creates:
# - C:\SecurityAudit\scan_results.json
# - C:\SecurityAudit\scan_report.html
# - C:\SecurityAudit\scan_summary.csv
```

### 3. Quick Vulnerability Check
```bash
# Fast scan focusing on high-risk areas
./sysrecon.exe --quick --verbose

# Scans only critical security areas:
# - Administrator accounts
# - Running services
# - Active network connections
```

### 4. Specific Module Analysis
```bash
# Scan only user accounts and services
./sysrecon.exe --modules accounts,services --output ./user_audit/

# Scan network configuration only
./sysrecon.exe --modules network --format json
```

### 5. Stealth Mode Operation
```bash
# Run with minimal system impact
./sysrecon.exe --stealth --quick --output ./stealth_scan/

# Features:
# - Reduced logging
# - Lower CPU priority
# - Minimal disk I/O
```

## 📊 Sample Output Formats

### JSON Output (scan_results.json)
```json
{
  "scan_info": {
    "version": "1.0.0",
    "timestamp": "20251014_143022",
    "hostname": "WORKSTATION-01",
    "os_version": "Windows 11 (Build 22000)",
    "scan_duration": "00:02:34",
    "modules_run": ["accounts", "services", "processes", "network"]
  },
  "results": {
    "accounts": {
      "total_users": 8,
      "admin_accounts": 2,
      "enabled_accounts": 6,
      "high_risk_findings": [
        {
          "type": "AdminAccountEnabled",
          "username": "Administrator",
          "risk_level": "Critical",
          "description": "Built-in Administrator account is enabled"
        }
      ]
    },
    "services": {
      "total_services": 245,
      "running_services": 89,
      "auto_start_services": 156,
      "suspicious_services": []
    }
  }
}
```

### HTML Report Preview
The HTML report includes:
- Executive Summary Dashboard
- Risk Score Visualization
- Detailed Findings by Module
- Recommendations & Remediation Steps
- System Configuration Overview

### CSV Export (scan_summary.csv)
```csv
Module,Item,Risk Level,Status,Description,Recommendation
Accounts,Administrator,Critical,Enabled,"Built-in admin account active","Disable or rename account"
Services,RemoteRegistry,Medium,Running,"Remote registry access enabled","Disable if not required"
Network,Port445,High,Open,"SMB file sharing exposed","Configure firewall rules"
```

## 🔧 Advanced Configuration Examples

### Custom Configuration File
```json
{
  "general": {
    "verbose_output": true,
    "max_threads": 2,
    "timeout_seconds": 600
  },
  "modules": {
    "accounts": {
      "enabled": true,
      "check_password_policies": true,
      "find_unused_accounts": true
    },
    "memory": {
      "enabled": false,
      "reason": "Resource intensive"
    }
  },
  "output": {
    "output_directory": "C:\\SecurityReports\\",
    "generate_executive_summary": true,
    "compress_output": true
  }
}
```

### PowerShell Integration
```powershell
# Automated security scanning script
$OutputPath = "C:\Security\Reports\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -Path $OutputPath -ItemType Directory -Force

# Run SysRecon
$Process = Start-Process -FilePath ".\sysrecon.exe" -ArgumentList "--full", "--output", $OutputPath -Wait -PassThru

if ($Process.ExitCode -eq 0) {
    Write-Host "Security scan completed successfully" -ForegroundColor Green
    
    # Parse results
    $Results = Get-Content "$OutputPath\scan_results.json" | ConvertFrom-Json
    
    # Send alert if critical issues found
    $CriticalIssues = $Results.results | Where-Object { $_.risk_level -eq "Critical" }
    if ($CriticalIssues.Count -gt 0) {
        Send-MailMessage -To "security@company.com" -Subject "Critical Security Issues Detected" -Body "SysRecon found $($CriticalIssues.Count) critical issues"
    }
} else {
    Write-Host "Security scan failed with exit code: $($Process.ExitCode)" -ForegroundColor Red
}
```

### Scheduled Scanning
```batch
@echo off
REM Daily security scan script
set SCAN_DATE=%date:~-4,4%-%date:~-10,2%-%date:~-7,2%
set OUTPUT_DIR=C:\SecurityScans\%SCAN_DATE%

mkdir "%OUTPUT_DIR%" 2>nul

REM Run morning quick scan
C:\Tools\sysrecon.exe --quick --output "%OUTPUT_DIR%" --format json,html

REM Check exit code
if %ERRORLEVEL% equ 0 (
    echo Scan completed successfully >> "%OUTPUT_DIR%\scan.log"
) else (
    echo Scan failed with code %ERRORLEVEL% >> "%OUTPUT_DIR%\scan.log"
    REM Send alert email or notification
    echo Critical: Daily security scan failed | mail -s "SysRecon Alert" admin@company.com
)
```

## 🛡️ Real-World Scenarios

### 1. Incident Response
```bash
# Emergency security assessment
./sysrecon.exe --modules accounts,processes,network --format json --output ./incident_$(date +%Y%m%d_%H%M%S)/

# Focus areas:
# - Active user sessions
# - Suspicious processes
# - Network connections
# - Recent logons
```

### 2. Compliance Audit
```bash
# Comprehensive compliance scan
./sysrecon.exe --full --config compliance_config.json --output ./compliance_audit/

# Generates reports for:
# - SOX compliance
# - PCI DSS requirements
# - HIPAA security rules
# - ISO 27001 controls
```

### 3. Penetration Testing
```bash
# Pre-engagement reconnaissance
./sysrecon.exe --stealth --modules accounts,services,network --output ./pentest_recon/

# Identifies:
# - Attack surface
# - Privilege escalation paths
# - Lateral movement opportunities
# - Persistence mechanisms
```

### 4. System Hardening Validation
```bash
# Verify security baseline
./sysrecon.exe --config baseline_check.json --output ./hardening_validation/

# Validates:
# - Security policy enforcement
# - Service configuration
# - User account management
# - Network security controls
```

## 📈 Interpreting Results

### Risk Levels
- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant vulnerability that should be addressed soon
- **Medium**: Security weakness that should be remediated
- **Low**: Minor security concern or best practice deviation
- **Info**: Informational finding for awareness

### Common Findings
1. **Enabled Administrator Account** → Disable or rename
2. **Weak Password Policies** → Implement stronger requirements
3. **Unnecessary Services Running** → Disable unused services
4. **Open Network Ports** → Configure firewall rules
5. **Outdated Software** → Apply security updates
6. **Excessive User Privileges** → Implement least privilege

### Remediation Priority
1. Fix Critical and High risk findings first
2. Address Medium risk items based on business impact
3. Consider Low risk findings for security hardening
4. Use Info findings for security awareness

## 🔍 Troubleshooting Common Issues

### Permission Errors
```cmd
# Run as Administrator
runas /user:Administrator "cmd /c C:\Tools\sysrecon.exe"

# Or use PowerShell
Start-Process -FilePath "sysrecon.exe" -Verb RunAs
```

### Performance Issues
```json
// Reduce resource usage in config.json
{
  "general": {
    "max_threads": 1,
    "timeout_seconds": 900
  },
  "modules": {
    "memory": {
      "enabled": false
    }
  }
}
```

### Network Connectivity
```bash
# Offline mode (no external lookups)
./sysrecon.exe --offline --modules accounts,services,processes
```

This quick start guide should help you get started with SysRecon effectively! 🚀
