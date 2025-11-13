# SysRecon CLI Documentation

## Command-Line Interface

SysRecon now includes a comprehensive CLI with full argument parsing support.

### Basic Usage

```bash
sysrecon.exe                    # Run full scan with default settings
sysrecon.exe --help             # Show help message
sysrecon.exe --version          # Show version information
```

### General Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help message and exit |
| `-v, --version` | Display version information |
| `--verbose` | Enable verbose/debug output |
| `--quiet` | Suppress non-essential output |
| `--stealth` | Run in stealth mode (minimal footprint) |
| `--quick` | Quick scan mode (skip deep analysis) |

### Configuration Options

| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Load configuration from FILE (default: config.json) |
| `-o, --output DIR` | Set output directory (default: ./reports) |
| `-f, --format FORMAT` | Report format: json, csv, html, all (default: all) |

### Module Selection

By default, SysRecon runs a **full scan** of all modules. You can selectively scan specific modules:

| Option | Module | Description |
|--------|--------|-------------|
| `--accounts` | User Accounts | Enumerate local users and groups |
| `--services` | Windows Services | Analyze running and stopped services |
| `--processes` | Running Processes | List processes and loaded modules |
| `--network` | Network | Enumerate network connections and ports |
| `--registry` | Registry | Scan registry for persistence mechanisms |
| `--memory` | Process Memory | Analyze process memory (slow) |

## Usage Examples

### 1. Full System Scan (Default)

```bash
sysrecon.exe
```

Performs a complete scan of all modules and generates JSON, CSV, and HTML reports in `./reports/`.

### 2. Quick Verbose Scan

```bash
sysrecon.exe --quick --verbose
```

Runs a fast scan with detailed console output.

### 3. Selective Module Scanning

```bash
# Scan only user accounts and services
sysrecon.exe --accounts --services

# Scan only network connections
sysrecon.exe --network

# Scan processes and memory (comprehensive process analysis)
sysrecon.exe --processes --memory
```

### 4. Custom Output Configuration

```bash
# JSON report only to custom directory
sysrecon.exe -f json -o C:\security_audit

# Multiple formats specified
sysrecon.exe -f json -f html -o ./output

# All formats to specific directory
sysrecon.exe -f all -o D:\scans
```

### 5. Stealth Mode Scanning

```bash
# Silent stealth scan
sysrecon.exe --stealth --quiet

# Stealth with specific modules
sysrecon.exe --stealth --accounts --registry
```

### 6. Custom Configuration

```bash
# Use custom config file
sysrecon.exe --config custom_config.json

# Custom config with verbose output
sysrecon.exe -c audit_config.json --verbose
```

## Advanced Examples

### Security Audit Workflow

```bash
# 1. Quick reconnaissance
sysrecon.exe --quick --accounts --services

# 2. Full audit with all details
sysrecon.exe --verbose -o ./full_audit

# 3. Stealth persistence check
sysrecon.exe --stealth --registry --services
```

### Incident Response

```bash
# 1. Capture system state
sysrecon.exe --processes --network -f json -o ./incident_2024_11_13

# 2. Memory analysis
sysrecon.exe --memory --processes --verbose

# 3. Complete forensic capture
sysrecon.exe -f all --verbose -o ./forensics
```

### Penetration Testing

```bash
# 1. Initial enumeration
sysrecon.exe --quick --accounts --network

# 2. Service vulnerability scan
sysrecon.exe --services --verbose

# 3. Privilege escalation vectors
sysrecon.exe --accounts --services --registry
```

## Output Formats

### JSON Format
```bash
sysrecon.exe -f json
```
- Machine-readable format
- Complete data structure
- Ideal for automation and parsing
- File: `scan_YYYYMMDD_HHMMSS.json`

### CSV Format
```bash
sysrecon.exe -f csv
```
- Spreadsheet-compatible
- Flat data structure
- Easy to analyze in Excel
- File: `scan_YYYYMMDD_HHMMSS.csv`

### HTML Format
```bash
sysrecon.exe -f html
```
- Human-readable report
- Color-coded risk levels
- Formatted tables
- File: `scan_YYYYMMDD_HHMMSS.html`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - All operations completed |
| 1 | Failure - Error during scan or report generation |

## Best Practices

1. **Run with Administrator Privileges**: Many Windows APIs require elevated permissions
   ```bash
   # Right-click → Run as Administrator
   sysrecon.exe
   ```

2. **Use Stealth Mode for Red Team Operations**:
   ```bash
   sysrecon.exe --stealth --quick --quiet
   ```

3. **Save Logs for Compliance**:
   ```bash
   sysrecon.exe --verbose -o ./compliance_audit_2024
   ```

4. **Selective Scanning for Performance**:
   ```bash
   # Fast scan (exclude memory analysis)
   sysrecon.exe --accounts --services --processes --network --registry
   ```

5. **Custom Configuration for Repeatable Scans**:
   ```bash
   sysrecon.exe -c monthly_audit.json -o ./audits/november
   ```

## Common Scenarios

### Scenario 1: Weekly Security Audit
```bash
sysrecon.exe -o "C:\Security\Audits\Week_$(date +%U)"
```

### Scenario 2: Pre-Deployment Check
```bash
sysrecon.exe --services --processes --network -f html
```

### Scenario 3: Compliance Documentation
```bash
sysrecon.exe --verbose -f all -o "Compliance_$(date +%Y%m%d)"
```

### Scenario 4: Troubleshooting Network Issues
```bash
sysrecon.exe --network --processes -f json
```

## Tips & Tricks

- Use `--verbose` to see what SysRecon is doing in real-time
- Use `--quiet` for cron jobs or scheduled tasks
- Combine `--quick` with selective modules for faster scans
- JSON format is best for integration with SIEM systems
- HTML format is best for management reports
- CSV format is best for detailed analysis in spreadsheet tools

## Troubleshooting

### Issue: "Access Denied" errors
**Solution**: Run as Administrator

### Issue: Reports not generating
**Solution**: Check output directory permissions with `--verbose`

### Issue: Slow scan
**Solution**: Use `--quick` or select specific modules instead of full scan

### Issue: Missing data in reports
**Solution**: Ensure Administrator privileges and disable antivirus temporarily

## Future CLI Enhancements

Planned features for future versions:
- [ ] `--exclude MODULE` to skip specific modules
- [ ] `--timeout SECONDS` for module execution limits
- [ ] `--threads N` for parallel scanning
- [ ] `--baseline FILE` to compare against previous scan
- [ ] `--diff SCAN1 SCAN2` to compare two scans
- [ ] `--watch` for continuous monitoring mode
- [ ] `--schedule CRON` for automated scanning
- [ ] `--remote HOST` for remote system scanning

---

**For more information, run:** `sysrecon.exe --help`
