#Requires -Version 7
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    End-to-end test of the SysRecon installer and binary on a real Windows host.

.DESCRIPTION
    Covers what the Linux/wine CI cannot: Windows APIs wine does not implement
    (local accounts, password policy, shares, the firewall service) and the
    installer's real behaviour (silent install, PATH, upgrade, silent
    uninstall).

    Every external process runs under a timeout, so a hang -- such as the
    silent-uninstall prompt that used to block forever -- fails the run
    instead of stalling it.

    Used by the `windows-test` CI job. Also runnable by hand in a disposable
    Windows VM (it installs and then uninstalls SysRecon):

        pwsh -File tests\windows\smoke-test.ps1 -Installer .\SysRecon-Setup-1.7.1.exe

.PARAMETER Installer
    Path to SysRecon-Setup-<version>.exe.

.PARAMETER OutDir
    Where logs and copies of the generated reports are kept.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) 'sysrecon-smoke')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Installer = (Resolve-Path -LiteralPath $Installer).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$InstallDir = Join-Path $env:ProgramFiles 'SysRecon'
$Exe = Join-Path $InstallDir 'sysrecon.exe'
$ReportsDir = Join-Path $InstallDir 'reports'

$script:TestTitle = 'SysRecon Windows smoke test'
. (Join-Path $PSScriptRoot 'common.ps1')

trap {
    Write-Annotation error "Aborted: $($_.Exception.Message)"
    break
}

# The installer is a 32-bit process without SetRegView, so its keys live in
# the 32-bit registry view (WOW6432Node).
function Get-Reg32([string]$SubKey, [string]$Value) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
    try {
        $key = $base.OpenSubKey($SubKey)
        if ($null -eq $key) { return $null }
        try { return $key.GetValue($Value) } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Test-Reg32Key([string]$SubKey) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
    try {
        $key = $base.OpenSubKey($SubKey)
        if ($null -eq $key) { return $false }
        $key.Dispose()
        return $true
    } finally { $base.Dispose() }
}

function Test-MachinePathContains([string]$Dir) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    return @($path -split ';' | Where-Object { $_ -ieq $Dir }).Count -gt 0
}

# Runs sysrecon.exe with a JSON report into a fresh directory and returns the
# parsed report (or $null).
function Invoke-Scan {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Arguments,
        [int]$ExpectedExit = 0
    )
    $dir = Join-Path $OutDir $Name
    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
    $code = Invoke-Timed -File $Exe -Arguments "$Arguments -o `"$dir`"" -TimeoutSec 900 -Name $Name
    Assert-True ($code -eq $ExpectedExit) "$Name exits $ExpectedExit (got $code)"
    $json = Get-ChildItem -LiteralPath $dir -Filter 'scan_*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $json) { return $null }
    return Get-Content -Raw -LiteralPath $json.FullName | ConvertFrom-Json
}

function Assert-ScanComplete($Report, [string]$Name) {
    Assert-True ($null -ne $Report) "$Name produced a JSON report"
    if ($null -eq $Report) { return }
    Assert-True ($Report.scan_info.elevated -eq $true) "$Name ran elevated"
    $incomplete = @($Report.incomplete_checks)
    Assert-True ($incomplete.Count -eq 0) "$Name has no incomplete checks"
    foreach ($note in $incomplete) {
        Write-Host "         incomplete: $note" -ForegroundColor Yellow
        Write-Annotation warning "$Name incomplete check: $note"
    }
    Assert-True ($Report.summary.total -eq @($Report.results).Count) "$Name summary total matches results"
}

# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $InstallDir) {
    throw "$InstallDir already exists; run this on a host without SysRecon installed."
}

Write-Step 'Silent install with /ADDTOPATH'
$code = Invoke-Timed -File $Installer -Arguments '/S /ADDTOPATH' -TimeoutSec 300 -Name 'install'
Assert-True ($code -eq 0) "installer exits 0 (got $code)"
foreach ($f in 'sysrecon.exe', 'config.json', 'configs\default.json', 'README.txt', 'LICENSE', 'Uninstall.exe') {
    Assert-True (Test-Path -LiteralPath (Join-Path $InstallDir $f)) "installed $f"
}
Assert-True (Test-Path -LiteralPath $ReportsDir) 'created reports directory'
Assert-True ((Get-Reg32 'Software\SysRecon' 'InstallDir') -eq $InstallDir) 'InstallDir registered'
Assert-True ((Get-Reg32 'Software\SysRecon' 'AddedToPath') -eq 1) 'AddedToPath recorded'
Assert-True (Test-Reg32Key 'Software\Microsoft\Windows\CurrentVersion\Uninstall\SysRecon') 'uninstall entry registered'
Assert-True (Test-MachinePathContains $InstallDir) 'install directory added to machine PATH'

# Shortcuts: scan shortcuts must request elevation (SLDF_RUNAS_USER, bit 0x20
# of byte 0x15); --help does not need it.
function Test-RunAsShortcut([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    return $bytes.Length -gt 0x15 -and (($bytes[0x15] -band 0x20) -ne 0)
}
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'SysRecon'
$desktop = [Environment]::GetFolderPath('Desktop')
foreach ($lnk in (Join-Path $startMenu 'SysRecon.lnk'), (Join-Path $startMenu 'Quick Scan.lnk'), (Join-Path $desktop 'SysRecon.lnk')) {
    $exists = Test-Path -LiteralPath $lnk
    Assert-True $exists "shortcut created: $lnk"
    if ($exists) { Assert-True (Test-RunAsShortcut $lnk) "shortcut requests elevation: $(Split-Path -Leaf $lnk)" }
}
$helpLnk = Join-Path $startMenu 'SysRecon Help.lnk'
if (Test-Path -LiteralPath $helpLnk) {
    Assert-True (-not (Test-RunAsShortcut $helpLnk)) 'help shortcut does not request elevation'
}

Write-Step '--help'
$code = Invoke-Timed -File $Exe -Arguments '--help' -TimeoutSec 60 -Name 'help'
$help = Get-Output 'help'
Assert-True ($code -eq 0) '--help exits 0'
Assert-True ($null -ne $help -and $help.Contains('--all')) '--help output captured when redirected'

Write-Step 'Default scan from another directory (config found next to the exe)'
Get-ChildItem -LiteralPath $ReportsDir -Filter 'scan_*' -ErrorAction SilentlyContinue | Remove-Item -Force
$code = Invoke-Timed -File $Exe -Arguments '-f json' -TimeoutSec 900 -Name 'scan-default' -WorkingDirectory $OutDir
Assert-True ($code -eq 0) "default scan exits 0 (got $code)"
$scanOut = Get-Output 'scan-default'
Assert-True ($null -ne $scanOut -and $scanOut.Contains('[SUMMARY]')) 'scan console output captured when redirected'
Assert-True ($null -ne $scanOut -and $scanOut.Contains([string][char]0x2550)) 'non-ASCII banner characters survive redirection as UTF-8'
$json = Get-ChildItem -LiteralPath $ReportsDir -Filter 'scan_*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
Assert-True ($null -ne $json) 'report written to the install directory reports folder, not the working directory'
if ($json) {
    $report = Get-Content -Raw -LiteralPath $json.FullName | ConvertFrom-Json
    Assert-ScanComplete $report 'default scan'
    Assert-True ($report.scan_info.config -ieq (Join-Path $InstallDir 'config.json')) "used installed config ($($report.scan_info.config))"
    # Expected selection = the modules the installed config enables, in
    # execution order (scan_plan.cpp AllScanModules). Derived rather than
    # hardcoded so adding a default-on module does not break this check.
    $order = [ordered]@{
        accounts = 'Accounts'; services = 'Services'; processes = 'Processes'; network = 'Network'
        registry = 'Registry'; memory = 'Memory'; privesc = 'Privilege Escalation'; domain = 'Domain'
    }
    $installedCfg = Get-Content -Raw -LiteralPath (Join-Path $InstallDir 'config.json') | ConvertFrom-Json
    $expected = @($order.Keys | Where-Object {
        $installedCfg.modules.PSObject.Properties.Name -contains $_ -and $installedCfg.modules.$_.enabled
    } | ForEach-Object { $order[$_] }) -join ','
    $modules = @($report.scan_info.modules) -join ','
    Assert-True ($modules -eq $expected) "config module selection applied ($modules; expected $expected)"
    Assert-True (-not (@($report.scan_info.modules) -contains 'Memory')) 'Memory module off by default'

    # Severity profile of a clean CI host, published so false-positive floods
    # are visible without downloading the report (a run once showed ~260
    # Critical findings from a broken service-DACL check).
    $serious = @($report.results | Where-Object { $_.risk_level -in 'Critical', 'High' })
    $groups = $serious | Group-Object { "$($_.risk_level) | $($_.module) | $(($_.item -split ':')[0])" } |
        Sort-Object Count -Descending | Select-Object -First 15
    $summary = ($groups | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join "`n"
    $critical = @($serious | Where-Object risk_level -eq 'Critical').Count
    Write-Annotation notice "Default scan on a clean host: $critical Critical, $($serious.Count - $critical) High`n$summary"
    Assert-True ($critical -le 10) "clean host does not produce a flood of Critical findings ($critical)"
    Assert-True (@($report.results | Where-Object { $_.module -eq 'User Accounts' }).Count -gt 0) 'local accounts enumerated'
    Copy-Item -Recurse -Force -LiteralPath $ReportsDir -Destination (Join-Path $OutDir 'installed-reports')
}
Assert-True (Test-Path -LiteralPath (Join-Path $ReportsDir 'sysrecon.log')) 'log file written'

Write-Step 'Selective scan, all formats'
$dir = Join-Path $OutDir 'scan-accounts'
$code = Invoke-Timed -File $Exe -Arguments "--accounts -f all -o `"$dir`"" -TimeoutSec 600 -Name 'scan-accounts'
Assert-True ($code -eq 0) "--accounts exits 0 (got $code)"
$csv = Get-ChildItem -LiteralPath $dir -Filter 'scan_*.csv' -ErrorAction SilentlyContinue | Select-Object -First 1
$html = Get-ChildItem -LiteralPath $dir -Filter 'scan_*.html' -ErrorAction SilentlyContinue | Select-Object -First 1
$jsonA = Get-ChildItem -LiteralPath $dir -Filter 'scan_*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
Assert-True ($null -ne $csv -and $null -ne $html -and $null -ne $jsonA) 'json, csv and html reports written'
if ($csv) {
    $bytes = [IO.File]::ReadAllBytes($csv.FullName)
    Assert-True ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'CSV has UTF-8 BOM'
}
if ($html) {
    Assert-True ((Get-Content -Raw -LiteralPath $html.FullName).StartsWith('<!DOCTYPE html>')) 'HTML report well-formed start'
}
# Reports carry usernames, SIDs and admin membership: only SYSTEM,
# Administrators and the owner may read them, whatever the folder grants.
foreach ($report in @($csv, $html, $jsonA) | Where-Object { $_ }) {
    $acl = Get-Acl -LiteralPath $report.FullName
    $users = @($acl.Access | Where-Object {
        $_.IdentityReference.Value -match '\\Users$|^Everyone$|Authenticated Users$' })
    Assert-True ($acl.AreAccessRulesProtected) "$($report.Extension) report ACL does not inherit from the folder"
    Assert-True ($users.Count -eq 0) "$($report.Extension) report not readable by Users/Everyone"
}
if ($jsonA) {
    $r = Get-Content -Raw -LiteralPath $jsonA.FullName | ConvertFrom-Json
    Assert-ScanComplete $r '--accounts scan'
    Assert-True ((@($r.scan_info.modules) -join ',') -eq 'Accounts') 'only the Accounts module ran'
}

Write-Step 'Quick scan'
$r = Invoke-Scan -Name 'scan-quick' -Arguments '--quick -f json'
Assert-ScanComplete $r 'quick scan'
if ($r) {
    Assert-True (@($r.results | Where-Object { $_.item -eq 'Listening TCP ports' }).Count -eq 1) 'quick scan enumerates listening ports'
}

Write-Step 'Stealth scan'
$r = Invoke-Scan -Name 'scan-stealth' -Arguments '--stealth --processes -f json'
Assert-ScanComplete $r 'stealth scan'
if ($r) { Assert-True ($r.scan_info.stealth_mode -eq $true) 'stealth recorded in report' }
$out = Get-Output 'scan-stealth'
Assert-True ($null -eq $out -or -not $out.Contains('[INFO]')) 'stealth mode writes no log lines to the console'

Write-Step 'Error handling'
$code = Invoke-Timed -File $Exe -Arguments '-c missing-config.json' -TimeoutSec 60 -Name 'err-missing-config'
Assert-True ($code -eq 1) "missing -c file exits 1 (got $code)"
$bad = Join-Path $OutDir 'bad-config.json'
Set-Content -LiteralPath $bad -Value '{"general": {"verbose_output": "yes"}}' -Encoding utf8
$code = Invoke-Timed -File $Exe -Arguments "-c `"$bad`"" -TimeoutSec 60 -Name 'err-bad-config'
Assert-True ($code -eq 1) "invalid config exits 1 (got $code)"
$code = Invoke-Timed -File $Exe -Arguments '--stealth --memory' -TimeoutSec 60 -Name 'err-stealth-memory'
Assert-True ($code -eq 1) "--stealth --memory (nothing left to run) exits 1 (got $code)"

Write-Step 'Interactive mode exits on end of input'
$empty = Join-Path $OutDir 'empty-stdin.txt'
Set-Content -LiteralPath $empty -Value '' -NoNewline
$code = Invoke-Timed -File $Exe -TimeoutSec 60 -Name 'interactive-eof' -StdinFile $empty
Assert-True ($code -eq 0) "interactive mode exits 0 on EOF (got $code)"

Write-Step 'Upgrade install keeps the operator''s config.json'
$configPath = Join-Path $InstallDir 'config.json'
$cfg = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
$cfg.general.verbose_output = $true
$cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding utf8
$code = Invoke-Timed -File $Installer -Arguments '/S' -TimeoutSec 300 -Name 'upgrade'
Assert-True ($code -eq 0) "upgrade install exits 0 (got $code)"
$after = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
Assert-True ($after.general.verbose_output -eq $true) 'edited config.json survived the upgrade'
$default = Get-Content -Raw -LiteralPath (Join-Path $InstallDir 'configs\default.json') | ConvertFrom-Json
Assert-True ($default.general.verbose_output -eq $false) 'configs\default.json holds the shipped default'

Write-Step 'Silent uninstall'
# _?= runs the uninstaller in place so this process can wait for it (by
# default it copies itself to %TEMP% and returns immediately).
$code = Invoke-Timed -File (Join-Path $InstallDir 'Uninstall.exe') -Arguments "/S _?=$InstallDir" -TimeoutSec 120 -Name 'uninstall'
Assert-True ($code -eq 0) "silent uninstall finishes without prompting (exit $code)"
Assert-True (-not (Test-Path -LiteralPath $Exe)) 'sysrecon.exe removed'
Assert-True (-not (Test-Path -LiteralPath $configPath)) 'config.json removed'
Assert-True (-not (Test-Reg32Key 'Software\SysRecon')) 'Software\SysRecon key removed'
Assert-True (-not (Test-Reg32Key 'Software\Microsoft\Windows\CurrentVersion\Uninstall\SysRecon')) 'uninstall entry removed'
Assert-True (-not (Test-MachinePathContains $InstallDir)) 'install directory removed from machine PATH'
Assert-True (Test-Path -LiteralPath $ReportsDir) 'silent uninstall keeps reports (user data)'
Assert-True (-not (Test-Path -LiteralPath $startMenu)) 'Start Menu folder removed'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $desktop 'SysRecon.lnk'))) 'desktop shortcut removed'

# With _?= the uninstaller leaves itself and the directory behind.
Remove-Item -Recurse -Force -LiteralPath $InstallDir -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Complete-Test
