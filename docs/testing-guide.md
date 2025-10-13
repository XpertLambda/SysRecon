# SysRecon - Testing on Windows

## Overview
This document explains how to cross-compile SysRecon on Arch Linux and test it on Windows systems.

## Prerequisites

### On Arch Linux (Development System)
- CMake 3.20+
- MinGW-w64 cross-compilation toolchain
- Make and base-devel

```bash
sudo pacman -S cmake mingw-w64-gcc make base-devel
```

## Current Build Status

⚠️ **Note**: The project currently has some compilation issues related to header dependencies that need to be resolved. The architecture and structure are complete, but type definitions need to be reorganized to avoid circular dependencies.

## Steps to Build (Once Fixed)

### 1. Build on Arch Linux
```bash
cd /home/xpert/Desktop/Projects/SysRecon
./build.sh release
```

This will:
- Configure the project for Windows x64 target
- Cross-compile using MinGW-w64
- Create `sysrecon.exe` in the `build/` directory

### 2. Transfer to Windows
Transfer the following files to your Windows test machine:

```
sysrecon.exe        # Main executable
config.json         # Configuration file (optional)
README.md           # Documentation
```

**Transfer Methods:**
- USB drive
- Network share (SMB/CIFS)
- SCP/SFTP
- Cloud storage (Dropbox, Google Drive, etc.)

### 3. Test on Windows

#### Basic Test
```cmd
# Open Command Prompt as Administrator
cd C:\Path\To\SysRecon

# Check if it runs
sysrecon.exe --version

# View help
sysrecon.exe --help
```

#### Quick Scan
```cmd
# Run a quick security scan
sysrecon.exe --quick

# Specify output directory
sysrecon.exe --quick --output C:\Reports
```

#### Full System Audit
```cmd
# Complete system audit with all modules
sysrecon.exe --verbose

# Generate all report formats
sysrecon.exe --format all --output C:\SecurityAudit
```

#### Module-Specific Tests
```cmd
# Test user enumeration
sysrecon.exe --accounts --verbose

# Test service analysis
sysrecon.exe --services --verbose

# Test network assessment
sysrecon.exe --network --verbose

# Test registry analysis
sysrecon.exe --registry --verbose
```

## Testing Checklist

### ✅ Basic Functionality
- [ ] Application starts without errors
- [ ] Help message displays correctly
- [ ] Version information shows
- [ ] Configuration file loads properly

### ✅ Module Testing
- [ ] **Accounts Module**
  - [ ] Enumerates local users
  - [ ] Lists user groups
  - [ ] Identifies admin accounts
  - [ ] Detects password policies

- [ ] **Services Module**
  - [ ] Lists all services
  - [ ] Identifies startup services
  - [ ] Detects unquoted paths
  - [ ] Checks service permissions

- [ ] **Processes Module**
  - [ ] Enumerates running processes
  - [ ] Lists loaded modules/DLLs
  - [ ] Identifies suspicious processes

- [ ] **Network Module**
  - [ ] Lists listening ports
  - [ ] Shows active connections
  - [ ] Enumerates network interfaces
  - [ ] Identifies network shares

- [ ] **Registry Module**
  - [ ] Scans startup keys
  - [ ] Analyzes security policies
  - [ ] Checks registry permissions
  - [ ] Detects persistence mechanisms

### ✅ Report Generation
- [ ] JSON report creates successfully
- [ ] CSV report is properly formatted
- [ ] HTML report opens in browser
- [ ] Reports contain expected data
- [ ] Output directory is created

### ✅ Security Testing
- [ ] Runs without admin privileges (limited)
- [ ] Runs with admin privileges (full features)
- [ ] Doesn't trigger false AV alerts
- [ ] Stealth mode operates quietly
- [ ] No system instability

### ✅ Performance Testing
- [ ] Completes scan in reasonable time
- [ ] CPU usage stays below 25%
- [ ] Memory usage is acceptable
- [ ] No memory leaks during long scans

## Expected Output

### Console Output
```
  ███████╗██╗   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ███████╗ ╚████╔╝ ███████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ╚════██║  ╚██╔╝  ╚════██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ███████║   ██║   ███████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

  SysRecon - Windows Audit Tool 2025 v1.0.0
  Professional Windows Security Assessment & Forensic Analysis

[INFO] Initializing SysRecon scan engine
[INFO] Starting full system scan
[INFO] Enumerating user accounts...
[INFO] Enumerating Windows services...
[INFO] Enumerating running processes...
[INFO] Enumerating network connections...
[INFO] Analyzing registry startup keys...
[INFO] Generating reports...

=== SCAN SUMMARY ===
Total findings: 45
  Critical: 2
  High:     8
  Medium:   15
  Low:      20

Reports generated successfully.
```

### Generated Reports
```
reports/
├── sysrecon_report_20251007_143022.html
├── sysrecon_report_20251007_143022.json
└── sysrecon_report_20251007_143022.csv
```

## Troubleshooting

### Issue: "Access Denied" Errors
**Solution**: Run Command Prompt as Administrator

### Issue: Antivirus Blocks Execution
**Solution**: Add SysRecon to AV exclusions or temporarily disable AV

### Issue: Missing DLL Errors
**Solution**: The executable should be statically linked. If you see this error, rebuild with `-static` flags.

### Issue: No Output Files Generated
**Solution**: Check write permissions in output directory and ensure disk space

### Issue: Slow Performance
**Solution**: 
- Reduce thread count in config.json
- Use `--quick` mode for faster scans
- Disable memory analysis module

## Development Testing

### Debugging on Windows
If you have Visual Studio or MinGW on Windows, you can also compile natively:

```cmd
# Using MinGW on Windows
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
mingw32-make
```

### Test in Virtual Machine
Recommended for safe testing:
- Windows 10/11 VM in VirtualBox/VMware
- Take snapshot before testing
- Test with various privilege levels
- Test on different Windows versions

## Next Steps After Successful Build

1. **Complete the Windows API implementations** in each module
2. **Add comprehensive error handling**
3. **Implement JSON parsing** for configuration
4. **Add unit tests** for core functionality
5. **Test on multiple Windows versions**
6. **Add code signing** for production deployment
7. **Create installer** (MSI/NSIS)

## Known Limitations (Current State)

- Module implementations are stubs (need Windows API integration)
- JSON configuration parsing not yet implemented  
- PDF report generation requires external library
- Some advanced features require administrator privileges
- Memory analysis is resource-intensive

## Security Considerations

### Before Testing
- Get proper authorization for scanning systems
- Review applicable policies and regulations
- Document testing scope and objectives

### During Testing
- Monitor system performance
- Watch for unexpected behavior
- Document all findings
- Keep scan logs for audit trail

### After Testing
- Securely store generated reports
- Review findings with appropriate personnel
- Follow responsible disclosure practices
- Clean up test artifacts

## Contact & Support

For build issues or questions:
- Check project documentation in `docs/`
- Review README.md for detailed information
- Check GitHub issues (if applicable)
- Contact development team

---

**Important**: Always ensure you have proper authorization before running security assessment tools on any system!
