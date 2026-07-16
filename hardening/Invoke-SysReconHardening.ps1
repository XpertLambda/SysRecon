#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies a CIS Level 1 (workstation) aligned security baseline to a Windows
    host, with dry-run preview, full backup, and rollback.

.DESCRIPTION
    This is the WRITE-CAPABLE companion to SysRecon. SysRecon itself
    (sysrecon.exe) is strictly read-only and never changes the system; this
    script is the ONLY component that modifies settings. It is deliberately a
    separate, opt-in, elevated script so the audit tool keeps its read-only
    guarantee.

    The intended loop is:
        sysrecon.exe            (audit  -> findings)
        Invoke-SysReconHardening.ps1 -Apply   (remediate)
        sysrecon.exe            (re-audit -> confirm findings cleared)

    SAFETY MODEL (this is the point of the script, not an extra):
      * Dry-run by default. Nothing is changed unless you pass -Apply. Without
        it, every control is evaluated and the exact change set is printed.
      * Reversible. Before the first change, a timestamped backup bundle is
        written (registry exports, secedit template, auditpol backup, firewall
        export, service start types) and a System Restore point is attempted.
        Restore with:  -Rollback <bundle path>.
      * Idempotent. Every control reads current state and only writes on drift,
        so re-running a hardened machine reports zero changes.
      * Scoped. -Level 1 (default) is designed not to break normal use. -Level 2
        and destructive controls (-EnableBitLocker, -DisableRDP,
        -EnableCredentialGuard) are opt-in.

    This is a pragmatic scripted subset of CIS L1 for a standalone/workgroup
    Windows workstation. It is NOT a replacement for the full CIS-CAT tooling or
    the Microsoft Security Baseline GPOs. See docs/HARDENING.md for the complete
    control catalogue, CIS references, and per-control breakage notes.

.PARAMETER Apply
    Actually apply changes. Without this switch the script runs in preview
    (audit) mode and changes nothing.

.PARAMETER Level
    1 (default) = CIS L1 workstation-safe controls only.
    2           = adds L2 / attack-surface-reduction controls that are more
                  likely to affect apps, remote access, or domain workflows.

.PARAMETER Include
    Only run these control families (see -ListControls). Overrides -Level's set.

.PARAMETER Exclude
    Run everything selected by -Level except these families.

.PARAMETER ListControls
    Print the available control families and exit.

.PARAMETER Rollback
    Path to a backup bundle produced by a previous -Apply run. Restores the
    captured registry/policy/firewall/audit state and exits.

.PARAMETER BackupPath
    Root directory for backup bundles.
    Default: %ProgramData%\SysRecon\hardening-backups

.PARAMETER LogPath
    Transcript log file. Default: <BackupPath>\<stamp>\transcript.log

.PARAMETER EnableBitLocker
    Opt-in. Enable BitLocker on the OS volume. REQUIRES that you escrow the
    recovery key (the script prints it and saves it to the bundle; store it
    somewhere safe BEFORE rebooting). Off by default because a scripted enable
    without a stored key is a lockout risk.

.PARAMETER DisableRDP
    Opt-in. Fully disable Remote Desktop. Off by default because on a remote
    host this locks you out. Without this switch, RDP is only *hardened* if it
    is already enabled (NLA required, high encryption).

.PARAMETER EnableCredentialGuard
    Opt-in (L2). Enable Virtualization-Based Security / Credential Guard.
    Requires compatible hardware and can affect some drivers and third-party
    virtualization.

.EXAMPLE
    .\Invoke-SysReconHardening.ps1
    Preview every CIS L1 change on this host. Changes nothing.

.EXAMPLE
    .\Invoke-SysReconHardening.ps1 -Apply
    Back up, then apply the CIS L1 baseline.

.EXAMPLE
    .\Invoke-SysReconHardening.ps1 -Apply -Exclude Firewall,RDP
    Apply everything except the firewall and RDP controls.

.EXAMPLE
    .\Invoke-SysReconHardening.ps1 -Rollback 'C:\ProgramData\SysRecon\hardening-backups\2026-07-16_14-05-32'
    Restore the settings captured in that bundle.

.NOTES
    Some controls take effect only after a reboot (LSA protection, SMBv1 feature
    removal, Credential Guard). The script tells you when a reboot is required.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [ValidateSet(1, 2)][int]$Level = 1,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$ListControls,
    [string]$Rollback,
    [string]$BackupPath = (Join-Path $env:ProgramData 'SysRecon\hardening-backups'),
    [string]$LogPath,
    [switch]$EnableBitLocker,
    [switch]$DisableRDP,
    [switch]$EnableCredentialGuard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Script-wide state
# ---------------------------------------------------------------------------
$script:PreviewOnly = (-not $Apply) -or $WhatIfPreference
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:BundleDir = $null
$script:RebootRequired = $false
$script:Os = $null

# Registry keys captured wholesale into the backup bundle before any change.
$script:RegistryBackupKeys = @(
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
)

# Attack Surface Reduction rules (GUID -> description). CIS L1 subset; each is
# set to Block. See docs/HARDENING.md for what every rule blocks.
$script:AsrRules = [ordered]@{
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office apps creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Office apps creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Office apps injecting into other processes'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'JavaScript/VBScript launching downloaded executable content'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Obfuscated scripts'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Win32 API calls from Office macros'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Executable content from email/webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Executable files unless they meet prevalence/age/trust'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Credential stealing from LSASS'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Process creations from PSExec/WMI commands'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Untrusted/unsigned processes from USB'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Office communication apps creating child processes'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Adobe Reader creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Persistence through WMI event subscription'
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
function Write-HardenLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'CHANGE', 'SKIP', 'OK')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $color = switch ($Level) {
        'ERROR' { 'Red' }; 'WARN' { 'Yellow' }; 'CHANGE' { 'Cyan' }
        'OK' { 'Green' }; 'SKIP' { 'DarkGray' }; default { 'Gray' }
    }
    Write-Host ("[{0}] [{1,-6}] {2}" -f $ts, $Level, $Message) -ForegroundColor $color
}

function Register-Result {
    param(
        [string]$Control, [string]$Setting, $Current, $Desired,
        [ValidateSet('Compliant', 'WouldChange', 'Changed', 'Skipped', 'Failed')][string]$Status,
        [string]$Cis = '', [string]$Risk = 'Low', [string]$Note = ''
    )
    $script:Results.Add([pscustomobject]@{
            Control = $Control; Setting = $Setting
            Current = $Current; Desired = $Desired
            Status  = $Status; Cis = $Cis; Risk = $Risk; Note = $Note
        })
    switch ($Status) {
        'Compliant' { Write-HardenLog "$Control / $Setting already compliant" 'OK' }
        'WouldChange' { Write-HardenLog "$Control / $Setting : '$Current' -> '$Desired' (preview)" 'CHANGE' }
        'Changed' { Write-HardenLog "$Control / $Setting : '$Current' -> '$Desired' APPLIED" 'CHANGE' }
        'Skipped' { Write-HardenLog "$Control / $Setting skipped ($Note)" 'SKIP' }
        'Failed' { Write-HardenLog "$Control / $Setting FAILED ($Note)" 'ERROR' }
    }
}

# ---------------------------------------------------------------------------
# Core idempotent setters
# ---------------------------------------------------------------------------
function Set-RegistryValue {
    <#
        Idempotent registry write. Reads current, compares, and only writes on
        drift. In preview mode records the intended change without touching the
        registry.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')][string]$Type = 'DWord',
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$Setting,
        [string]$Cis = '', [string]$Risk = 'Low'
    )
    $current = $null
    try {
        if (Test-Path -LiteralPath $Path) {
            $prop = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $prop) { $current = $prop.$Name }
        }

        if ($null -ne $current -and "$current" -eq "$Value") {
            Register-Result $Control $Setting $current $Value 'Compliant' $Cis $Risk
            return
        }
        if ($script:PreviewOnly) {
            Register-Result $Control $Setting $current $Value 'WouldChange' $Cis $Risk
            return
        }
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Register-Result $Control $Setting $current $Value 'Changed' $Cis $Risk
    }
    catch {
        Register-Result $Control $Setting $current $Value 'Failed' $Cis $Risk $_.Exception.Message
    }
}

function Invoke-DriftAction {
    <#
        Generic non-registry control. Caller supplies a scriptblock that reads
        current state ($GetCurrent) and one that applies ($Apply). We compare to
        $Desired and only invoke $Apply on drift, honouring preview mode.
    #>
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][scriptblock]$GetCurrent,
        [Parameter(Mandatory)]$Desired,
        [Parameter(Mandatory)][scriptblock]$Apply,
        [string]$Cis = '', [string]$Risk = 'Low'
    )
    $current = $null
    try {
        $current = & $GetCurrent
        if ("$current" -eq "$Desired") {
            Register-Result $Control $Setting $current $Desired 'Compliant' $Cis $Risk
            return
        }
        if ($script:PreviewOnly) {
            Register-Result $Control $Setting $current $Desired 'WouldChange' $Cis $Risk
            return
        }
        & $Apply
        Register-Result $Control $Setting $current $Desired 'Changed' $Cis $Risk
    }
    catch {
        Register-Result $Control $Setting $current $Desired 'Failed' $Cis $Risk $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
function Get-OsProfile {
    $ci = Get-CimInstance -ClassName Win32_OperatingSystem
    $isServer = $ci.ProductType -ne 1          # 1 = workstation, 2 = DC, 3 = server
    $isDC = $ci.ProductType -eq 2
    $isHome = $ci.Caption -match 'Home'
    [pscustomobject]@{
        Caption  = $ci.Caption
        Build    = [int]$ci.BuildNumber
        IsServer = $isServer
        IsDC     = $isDC
        IsHome   = $isHome
        IsClient = -not $isServer
    }
}

# ---------------------------------------------------------------------------
# Backup / rollback
# ---------------------------------------------------------------------------
function New-BackupBundle {
    $stamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
    $dir = Join-Path $BackupPath $stamp
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $script:BundleDir = $dir
    Write-HardenLog "Backup bundle: $dir" 'INFO'

    # System Restore point (best effort; throttled to once per 24h on clients).
    try {
        if ($script:Os.IsClient) {
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description 'SysRecon hardening' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            Write-HardenLog 'System Restore point created' 'OK'
        }
    }
    catch {
        Write-HardenLog "System Restore point not created ($($_.Exception.Message)). Continuing; the bundle exports are the primary rollback." 'WARN'
    }

    # Registry keys.
    $regDir = Join-Path $dir 'registry'
    New-Item -ItemType Directory -Path $regDir -Force | Out-Null
    $i = 0
    foreach ($key in $script:RegistryBackupKeys) {
        $out = Join-Path $regDir ("key_{0:D2}.reg" -f $i)
        # Only export keys that exist; a missing key is restored by deleting on rollback is out of scope.
        $probe = 'Registry::' + $key
        if (Test-Path -LiteralPath $probe) {
            & reg.exe export $key $out /y *> $null
        }
        $i++
    }

    # Local security policy, audit policy, firewall.
    & secedit.exe /export /cfg (Join-Path $dir 'secpol-before.inf') /quiet *> $null
    & auditpol.exe /backup /file:(Join-Path $dir 'auditpol-before.csv') *> $null
    & netsh.exe advfirewall export (Join-Path $dir 'firewall-before.wfw') *> $null

    # Service start modes and SMB config, for reference / manual restore.
    try { Get-CimInstance Win32_Service | Select-Object Name, StartMode |
        Export-Csv (Join-Path $dir 'services-before.csv') -NoTypeInformation } catch { Write-Verbose $_.Exception.Message }
    try { Get-SmbServerConfiguration |
        Export-Clixml (Join-Path $dir 'smb-before.xml') } catch { Write-Verbose $_.Exception.Message }

    (@{
        created  = $stamp
        host     = $env:COMPUTERNAME
        os       = $script:Os.Caption
        level    = $Level
    } | ConvertTo-Json) | Set-Content -Path (Join-Path $dir 'manifest.json') -Encoding UTF8

    Write-HardenLog 'Backup complete' 'OK'
}

function Invoke-Rollback {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Rollback bundle not found: $Path"
    }
    Write-HardenLog "Rolling back from $Path" 'WARN'

    $regDir = Join-Path $Path 'registry'
    if (Test-Path $regDir) {
        Get-ChildItem $regDir -Filter '*.reg' | ForEach-Object {
            & reg.exe import $_.FullName *> $null
            Write-HardenLog "Imported $($_.Name)" 'OK'
        }
    }
    $sec = Join-Path $Path 'secpol-before.inf'
    if (Test-Path $sec) {
        & secedit.exe /configure /db "$env:windir\security\local.sdb" /cfg $sec /areas SECURITYPOLICY /quiet *> $null
        Write-HardenLog 'Restored local security policy' 'OK'
    }
    $aud = Join-Path $Path 'auditpol-before.csv'
    if (Test-Path $aud) {
        & auditpol.exe /restore /file:$aud *> $null
        Write-HardenLog 'Restored audit policy' 'OK'
    }
    $fw = Join-Path $Path 'firewall-before.wfw'
    if (Test-Path $fw) {
        & netsh.exe advfirewall import $fw *> $null
        Write-HardenLog 'Restored firewall configuration' 'OK'
    }

    Write-HardenLog 'Rollback complete. Some feature-level changes (SMBv1 removal, Credential Guard) and account-policy numbers may need manual review; a System Restore point was also created at hardening time as a backstop.' 'WARN'
}

# ---------------------------------------------------------------------------
# Control families
# ---------------------------------------------------------------------------
function Invoke-Control-Firewall {
    foreach ($p in @('Domain', 'Private', 'Public')) {
        Invoke-DriftAction -Control 'Firewall' -Setting "$p profile enabled" -Cis '9.1-9.3' `
            -GetCurrent { (Get-NetFirewallProfile -Profile $p).Enabled } -Desired 'True' `
            -Apply { Set-NetFirewallProfile -Profile $p -Enabled True }
        Invoke-DriftAction -Control 'Firewall' -Setting "$p default inbound" -Cis '9.1-9.3' `
            -GetCurrent { (Get-NetFirewallProfile -Profile $p).DefaultInboundAction } -Desired 'Block' `
            -Apply { Set-NetFirewallProfile -Profile $p -DefaultInboundAction Block }
        Invoke-DriftAction -Control 'Firewall' -Setting "$p log dropped" -Cis '9.x' `
            -GetCurrent { (Get-NetFirewallProfile -Profile $p).LogBlocked } -Desired 'True' `
            -Apply { Set-NetFirewallProfile -Profile $p -LogBlocked True }
    }
}

function Invoke-Control-SMB {
    Invoke-DriftAction -Control 'SMB' -Setting 'SMBv1 server protocol' -Cis '18.3.1' -Risk 'Low' `
        -GetCurrent { (Get-SmbServerConfiguration).EnableSMB1Protocol } -Desired 'False' `
        -Apply { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
    Invoke-DriftAction -Control 'SMB' -Setting 'Require SMB signing (server)' -Cis '2.3.9.x' `
        -GetCurrent { (Get-SmbServerConfiguration).RequireSecuritySignature } -Desired 'True' `
        -Apply { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force }
    Set-RegistryValue -Control 'SMB' -Setting 'Require SMB signing (client)' -Cis '2.3.8.1' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1
    Set-RegistryValue -Control 'SMB' -Setting 'Insecure guest logons' -Cis '18.5.x' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth' -Value 0

    # Remove the SMB1 optional feature (needs a reboot). Client SKUs only.
    if (-not $script:Os.IsServer) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            if ($f.State -eq 'Enabled') {
                if ($script:PreviewOnly) {
                    Register-Result 'SMB' 'SMB1 optional feature' 'Enabled' 'Disabled' 'WouldChange' '18.3.1' 'Low'
                }
                else {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                    $script:RebootRequired = $true
                    Register-Result 'SMB' 'SMB1 optional feature' 'Enabled' 'Disabled (reboot needed)' 'Changed' '18.3.1' 'Low'
                }
            }
            else {
                Register-Result 'SMB' 'SMB1 optional feature' 'Disabled' 'Disabled' 'Compliant' '18.3.1' 'Low'
            }
        }
        catch {
            Register-Result 'SMB' 'SMB1 optional feature' '?' 'Disabled' 'Skipped' '18.3.1' 'Low' 'feature query unavailable'
        }
    }
}

function Invoke-Control-UAC {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegistryValue -Control 'UAC' -Setting 'EnableLUA' -Cis '2.3.17.x' -Risk 'Medium' -Path $p -Name 'EnableLUA' -Value 1
    Set-RegistryValue -Control 'UAC' -Setting 'Admin approval prompt' -Cis '2.3.17.x' -Path $p -Name 'ConsentPromptBehaviorAdmin' -Value 2
    Set-RegistryValue -Control 'UAC' -Setting 'Prompt on secure desktop' -Cis '2.3.17.x' -Path $p -Name 'PromptOnSecureDesktop' -Value 1
    Set-RegistryValue -Control 'UAC' -Setting 'Installer detection' -Cis '2.3.17.x' -Path $p -Name 'EnableInstallerDetection' -Value 1
    Set-RegistryValue -Control 'UAC' -Setting 'UIAccess apps secure paths' -Cis '2.3.17.x' -Path $p -Name 'EnableSecureUIAPaths' -Value 1
}

function Invoke-Control-LegacyAuth {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'LM/NTLMv1 (LmCompatibilityLevel)' -Cis '2.3.11.7' -Risk 'Medium' -Path $lsa -Name 'LmCompatibilityLevel' -Value 5
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'No LM hash storage' -Cis '2.3.11.5' -Path $lsa -Name 'NoLMHash' -Value 1
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'RestrictAnonymous' -Cis '2.3.10.x' -Path $lsa -Name 'RestrictAnonymous' -Value 1
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'RestrictAnonymousSAM' -Cis '2.3.10.2' -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'WDigest UseLogonCredential' -Cis '18.x' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
    # LLMNR off.
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'LLMNR (multicast name resolution)' -Cis '18.5.4.2' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
    # NetBIOS node type P-node (disables NBT-NS broadcast).
    Set-RegistryValue -Control 'LegacyAuth' -Setting 'NetBIOS node type (P-node)' -Cis '18.x' -Risk 'Medium' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Value 2
}

function Invoke-Control-AccountPolicy {
    if ($script:Os.IsHome) {
        Register-Result 'AccountPolicy' 'password & lockout policy' 'n/a' 'CIS L1' 'Skipped' '1.1-1.2' 'Low' 'Home edition has no local policy engine'
        return
    }
    # Read current numbers from `net accounts`.
    $na = (& net.exe accounts) -join "`n"
    function Get-NA([string]$label) {
        $m = [regex]::Match($na, [regex]::Escape($label) + '\s*:\s*(\S+)')
        if ($m.Success) { return $m.Groups[1].Value } else { return $null }
    }
    $desired = @{
        'Minimum password length'         = @{ current = (Get-NA 'Minimum password length'); target = 14; op = 'min'; arg = 'minpwlen'; cis = '1.1.4' }
        'Maximum password age (days)'     = @{ current = (Get-NA 'Maximum password age (days)'); target = 365; op = 'max'; arg = 'maxpwage'; cis = '1.1.2' }
        'Minimum password age (days)'     = @{ current = (Get-NA 'Minimum password age (days)'); target = 1; op = 'min'; arg = 'minpwage'; cis = '1.1.3' }
        'Length of password history maintained' = @{ current = (Get-NA 'Length of password history maintained'); target = 24; op = 'min'; arg = 'uniquepw'; cis = '1.1.1' }
        'Lockout threshold'               = @{ current = (Get-NA 'Lockout threshold'); target = 5; op = 'lockout'; arg = 'lockoutthreshold'; cis = '1.2.2' }
        'Lockout duration (minutes)'      = @{ current = (Get-NA 'Lockout duration (minutes)'); target = 15; op = 'min'; arg = 'lockoutduration'; cis = '1.2.1' }
        'Lockout observation window (minutes)' = @{ current = (Get-NA 'Lockout observation window (minutes)'); target = 15; op = 'min'; arg = 'lockoutwindow'; cis = '1.2.3' }
    }
    foreach ($label in $desired.Keys) {
        $d = $desired[$label]
        $curRaw = $d.current
        $curNum = 0; [void][int]::TryParse($curRaw, [ref]$curNum)
        $isNever = $curRaw -match 'Never|Unlimited'
        $needChange = switch ($d.op) {
            'min' { $curNum -lt $d.target }
            'max' { $isNever -or $curNum -gt $d.target }
            'lockout' { $curNum -eq 0 -or $curNum -gt $d.target }   # 0 = never lock out
        }
        if (-not $needChange) {
            Register-Result 'AccountPolicy' $label $curRaw $d.target 'Compliant' $d.cis 'Low'
            continue
        }
        if ($script:PreviewOnly) {
            Register-Result 'AccountPolicy' $label $curRaw $d.target 'WouldChange' $d.cis 'Low'
            continue
        }
        try {
            & net.exe accounts ("/{0}:{1}" -f $d.arg, $d.target) *> $null
            Register-Result 'AccountPolicy' $label $curRaw $d.target 'Changed' $d.cis 'Low'
        }
        catch {
            Register-Result 'AccountPolicy' $label $curRaw $d.target 'Failed' $d.cis 'Low' $_.Exception.Message
        }
    }

    # Password complexity via a secedit template.
    Set-SecEditPolicy -Setting 'Password complexity' -InfSection 'System Access' -InfKey 'PasswordComplexity' -Value 1 -Cis '1.1.5'
}

function Set-SecEditPolicy {
    param(
        [string]$Setting, [string]$InfSection, [string]$InfKey, $Value,
        [string]$Cis = '', [string]$Risk = 'Low', [string]$Control = 'AccountPolicy'
    )
    try {
        $tmp = Join-Path $env:TEMP ("sysrecon_secedit_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        & secedit.exe /export /cfg $tmp /quiet *> $null
        $content = Get-Content $tmp -ErrorAction SilentlyContinue
        $current = $null
        $m = [regex]::Match(($content -join "`n"), [regex]::Escape($InfKey) + '\s*=\s*(\S+)')
        if ($m.Success) { $current = $m.Groups[1].Value }
        Remove-Item $tmp -ErrorAction SilentlyContinue

        if ("$current" -eq "$Value") {
            Register-Result $Control $Setting $current $Value 'Compliant' $Cis $Risk
            return
        }
        if ($script:PreviewOnly) {
            Register-Result $Control $Setting $current $Value 'WouldChange' $Cis $Risk
            return
        }
        $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[$InfSection]
$InfKey = $Value
"@
        $infFile = Join-Path $env:TEMP ("sysrecon_apply_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -Path $infFile -Value $inf -Encoding Unicode
        & secedit.exe /configure /db "$env:windir\security\local.sdb" /cfg $infFile /areas SECURITYPOLICY /quiet *> $null
        Remove-Item $infFile -ErrorAction SilentlyContinue
        Register-Result $Control $Setting $current $Value 'Changed' $Cis $Risk
    }
    catch {
        Register-Result $Control $Setting '?' $Value 'Failed' $Cis $Risk $_.Exception.Message
    }
}

function Invoke-Control-BuiltinAccounts {
    # Disable Guest.
    Invoke-DriftAction -Control 'Accounts' -Setting 'Guest account disabled' -Cis '1.x' `
        -GetCurrent {
            $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            if ($null -eq $g) { 'True' } else { (-not $g.Enabled).ToString() }
        } -Desired 'True' -Apply { Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue }
    # Deny blank-password use over the network.
    Set-RegistryValue -Control 'Accounts' -Setting 'Limit blank password use to console' -Cis '2.3.1.x' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1
}

function Invoke-Control-Defender {
    try { $null = Get-MpComputerStatus -ErrorAction Stop }
    catch {
        Register-Result 'Defender' 'Microsoft Defender' 'unavailable' 'enabled' 'Skipped' '18.9.x' 'Low' 'Defender not present or a third-party AV is active'
        return
    }
    Invoke-DriftAction -Control 'Defender' -Setting 'Real-time protection' -Cis '18.9.x' `
        -GetCurrent { (-not (Get-MpPreference).DisableRealtimeMonitoring).ToString() } -Desired 'True' `
        -Apply { Set-MpPreference -DisableRealtimeMonitoring $false }
    Invoke-DriftAction -Control 'Defender' -Setting 'PUA protection' -Cis '18.9.x' `
        -GetCurrent { (Get-MpPreference).PUAProtection } -Desired '1' `
        -Apply { Set-MpPreference -PUAProtection Enabled }
    Invoke-DriftAction -Control 'Defender' -Setting 'Cloud-delivered protection (MAPS)' -Cis '18.9.x' `
        -GetCurrent { (Get-MpPreference).MAPSReporting } -Desired '2' `
        -Apply { Set-MpPreference -MAPSReporting Advanced }
    Invoke-DriftAction -Control 'Defender' -Setting 'Submit samples (safe)' -Cis '18.9.x' `
        -GetCurrent { (Get-MpPreference).SubmitSamplesConsent } -Desired '1' `
        -Apply { Set-MpPreference -SubmitSamplesConsent SendSafeSamples }

    # ASR rules -> Block, only for those not already enabled.
    $pref = Get-MpPreference
    $enabledIds = @{}
    if ($pref.AttackSurfaceReductionRules_Ids) {
        for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $enabledIds[$pref.AttackSurfaceReductionRules_Ids[$i].ToLower()] = $pref.AttackSurfaceReductionRules_Actions[$i]
        }
    }
    foreach ($id in $script:AsrRules.Keys) {
        $desc = $script:AsrRules[$id]
        $isBlock = $enabledIds.ContainsKey($id.ToLower()) -and "$($enabledIds[$id.ToLower()])" -eq '1'
        if ($isBlock) {
            Register-Result 'Defender-ASR' $desc 'Block' 'Block' 'Compliant' '18.9.x' 'Medium'
            continue
        }
        if ($script:PreviewOnly) {
            Register-Result 'Defender-ASR' $desc 'not-block' 'Block' 'WouldChange' '18.9.x' 'Medium'
            continue
        }
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Register-Result 'Defender-ASR' $desc 'not-block' 'Block' 'Changed' '18.9.x' 'Medium'
        }
        catch {
            Register-Result 'Defender-ASR' $desc 'not-block' 'Block' 'Failed' '18.9.x' 'Medium' $_.Exception.Message
        }
    }
}

function Invoke-Control-AutoRun {
    Set-RegistryValue -Control 'AutoRun' -Setting 'Disable Autorun on all drives' -Cis '18.9.8.x' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
    Set-RegistryValue -Control 'AutoRun' -Setting 'No autorun for legacy media' -Cis '18.9.8.x' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1
}

function Invoke-Control-AuditPolicy {
    # Advanced audit subcategories: enable success+failure where CIS asks.
    $subs = @(
        @{ n = 'Logon'; s = $true; f = $true; cis = '17.5.x' },
        @{ n = 'Logoff'; s = $true; f = $false; cis = '17.5.x' },
        @{ n = 'Account Lockout'; s = $false; f = $true; cis = '17.5.x' },
        @{ n = 'Special Logon'; s = $true; f = $false; cis = '17.5.x' },
        @{ n = 'User Account Management'; s = $true; f = $true; cis = '17.2.x' },
        @{ n = 'Security Group Management'; s = $true; f = $true; cis = '17.2.x' },
        @{ n = 'Process Creation'; s = $true; f = $false; cis = '17.3.x' },
        @{ n = 'Sensitive Privilege Use'; s = $true; f = $true; cis = '17.7.x' },
        @{ n = 'Audit Policy Change'; s = $true; f = $false; cis = '17.7.x' },
        @{ n = 'Authentication Policy Change'; s = $true; f = $false; cis = '17.7.x' },
        @{ n = 'Security State Change'; s = $true; f = $false; cis = '17.9.x' },
        @{ n = 'Removable Storage'; s = $true; f = $true; cis = '17.6.x' }
    )
    foreach ($x in $subs) {
        Invoke-DriftAction -Control 'Audit' -Setting $x.n -Cis $x.cis `
            -GetCurrent {
                $line = (& auditpol.exe /get /subcategory:"$($x.n)" /r 2>$null | Select-String -Pattern ([regex]::Escape($x.n)))
                if ($line) {
                    $val = ($line.ToString() -split ',')[-1].Trim()
                    $sOn = $val -match 'Success'
                    $fOn = $val -match 'Failure'
                    (($sOn -ge $x.s) -and ($fOn -ge $x.f)).ToString()
                }
                else { 'False' }
            } -Desired 'True' -Apply {
                $apArgs = @('/set', "/subcategory:$($x.n)")
                if ($x.s) { $apArgs += '/success:enable' }
                if ($x.f) { $apArgs += '/failure:enable' }
                & auditpol.exe @apArgs *> $null
            }
    }
    # Include command line in process creation events.
    Set-RegistryValue -Control 'Audit' -Setting 'Command line in process creation' -Cis '18.x' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
    # Force audit-policy subcategory override.
    Set-RegistryValue -Control 'Audit' -Setting 'Force subcategory audit policy' -Cis '2.3.2.1' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1
    # Grow the Security event log to 196 MB.
    Set-RegistryValue -Control 'Audit' -Setting 'Security log max size (KB)' -Cis '17.1.x' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Value 201326592
}

function Invoke-Control-PowerShellLogging {
    $sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    Set-RegistryValue -Control 'PowerShell' -Setting 'Script block logging' -Cis '18.9.100.x' -Path $sb -Name 'EnableScriptBlockLogging' -Value 1
    $ml = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Set-RegistryValue -Control 'PowerShell' -Setting 'Module logging' -Cis '18.9.100.x' -Path $ml -Name 'EnableModuleLogging' -Value 1
    Set-RegistryValue -Control 'PowerShell' -Setting 'Module logging (all modules)' -Cis '18.9.100.x' -Path "$ml\ModuleNames" -Name '*' -Value '*' -Type String
    $tr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    Set-RegistryValue -Control 'PowerShell' -Setting 'Transcription' -Cis '18.9.100.x' -Path $tr -Name 'EnableTranscripting' -Value 1
    Set-RegistryValue -Control 'PowerShell' -Setting 'Transcription includes invocation headers' -Cis '18.9.100.x' -Path $tr -Name 'EnableInvocationHeader' -Value 1
}

function Invoke-Control-LSAProtection {
    Set-RegistryValue -Control 'LSA' -Setting 'LSASS run as protected process (RunAsPPL)' -Cis '18.4.x' -Risk 'Medium' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1
    $script:RebootRequired = $true
}

function Invoke-Control-InteractiveLogon {
    Set-RegistryValue -Control 'Logon' -Setting 'Machine inactivity limit (900s)' -Cis '2.3.7.x' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900
    Set-RegistryValue -Control 'Logon' -Setting 'Do not display last user name' -Cis '2.3.7.x' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1
    Set-RegistryValue -Control 'Logon' -Setting 'Cached logon count (4)' -Cis '2.3.7.x' -Risk 'Medium' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '4' -Type String
}

function Invoke-Control-RDP {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpEnabled = $false
    try {
        $deny = (Get-ItemProperty -LiteralPath $ts -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        $rdpEnabled = ($deny -eq 0)
    }
    catch { Write-Verbose $_.Exception.Message }

    if ($DisableRDP) {
        Set-RegistryValue -Control 'RDP' -Setting 'Deny RDP connections' -Cis '18.x' -Risk 'High' -Path $ts -Name 'fDenyTSConnections' -Value 1
        return
    }
    if (-not $rdpEnabled) {
        Register-Result 'RDP' 'Remote Desktop' 'disabled' 'disabled (not hardened - already off)' 'Compliant' '18.x' 'Low'
        return
    }
    # RDP is on: harden it rather than disable (disabling could lock out a remote admin).
    Set-RegistryValue -Control 'RDP' -Setting 'Require Network Level Authentication' -Cis '18.x' -Risk 'Medium' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
    Set-RegistryValue -Control 'RDP' -Setting 'Minimum encryption level (High)' -Cis '18.x' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3
    Set-RegistryValue -Control 'RDP' -Setting 'Do not allow saved passwords' -Cis '18.x' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1
}

# ----- L2 / opt-in ---------------------------------------------------------
function Invoke-Control-CredentialGuard {
    if (-not $EnableCredentialGuard) {
        Register-Result 'CredentialGuard' 'Virtualization-based Credential Guard' 'not requested' 'enabled' 'Skipped' '18.4.x' 'High' 'opt-in: pass -EnableCredentialGuard (needs compatible hardware)'
        return
    }
    $dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    Set-RegistryValue -Control 'CredentialGuard' -Setting 'Enable VBS' -Cis '18.4.x' -Risk 'High' -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1
    Set-RegistryValue -Control 'CredentialGuard' -Setting 'Platform security (Secure Boot)' -Cis '18.4.x' -Risk 'High' -Path $dg -Name 'RequirePlatformSecurityFeatures' -Value 1
    Set-RegistryValue -Control 'CredentialGuard' -Setting 'Credential Guard enabled' -Cis '18.4.x' -Risk 'High' -Path "$dg\Scenarios\CredentialGuard" -Name 'Enabled' -Value 1
    $script:RebootRequired = $true
}

function Invoke-Control-WSH {
    Set-RegistryValue -Control 'WSH' -Setting 'Disable Windows Script Host' -Cis 'L2' -Risk 'High' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0
}

function Invoke-Control-BitLocker {
    if (-not $EnableBitLocker) {
        Register-Result 'BitLocker' 'OS volume encryption' 'not requested' 'encrypted' 'Skipped' '18.9.x' 'High' 'opt-in: pass -EnableBitLocker AND store the recovery key before reboot'
        return
    }
    try { $null = Get-Command Enable-BitLocker -ErrorAction Stop }
    catch {
        Register-Result 'BitLocker' 'OS volume encryption' 'unavailable' 'encrypted' 'Skipped' '18.9.x' 'High' 'BitLocker not available on this edition'
        return
    }
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($vol -and $vol.ProtectionStatus -eq 'On') {
        Register-Result 'BitLocker' 'OS volume encryption' 'On' 'On' 'Compliant' '18.9.x' 'High'
        return
    }
    if ($script:PreviewOnly) {
        Register-Result 'BitLocker' 'OS volume encryption' 'Off' 'On' 'WouldChange' '18.9.x' 'High'
        return
    }
    try {
        Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
        $key = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector |
            Where-Object KeyProtectorType -eq 'RecoveryPassword'
        if ($key -and $script:BundleDir) {
            $keyFile = Join-Path $script:BundleDir 'BitLocker-RecoveryKey.txt'
            "Recovery Key for $env:COMPUTERNAME $env:SystemDrive`n$($key.RecoveryPassword)" |
                Set-Content -Path $keyFile -Encoding UTF8
            Write-HardenLog "BitLocker recovery key saved to $keyFile - MOVE IT OFF THIS MACHINE." 'WARN'
        }
        $script:RebootRequired = $true
        Register-Result 'BitLocker' 'OS volume encryption' 'Off' 'On' 'Changed' '18.9.x' 'High' 'recovery key saved to bundle'
    }
    catch {
        Register-Result 'BitLocker' 'OS volume encryption' 'Off' 'On' 'Failed' '18.9.x' 'High' $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Control registry (name -> function, minimum level)
# ---------------------------------------------------------------------------
$script:ControlTable = [ordered]@{
    'Firewall'        = @{ fn = 'Invoke-Control-Firewall'; level = 1 }
    'SMB'             = @{ fn = 'Invoke-Control-SMB'; level = 1 }
    'UAC'             = @{ fn = 'Invoke-Control-UAC'; level = 1 }
    'LegacyAuth'      = @{ fn = 'Invoke-Control-LegacyAuth'; level = 1 }
    'AccountPolicy'   = @{ fn = 'Invoke-Control-AccountPolicy'; level = 1 }
    'BuiltinAccounts' = @{ fn = 'Invoke-Control-BuiltinAccounts'; level = 1 }
    'Defender'        = @{ fn = 'Invoke-Control-Defender'; level = 1 }
    'AutoRun'         = @{ fn = 'Invoke-Control-AutoRun'; level = 1 }
    'AuditPolicy'     = @{ fn = 'Invoke-Control-AuditPolicy'; level = 1 }
    'PowerShell'      = @{ fn = 'Invoke-Control-PowerShellLogging'; level = 1 }
    'LSAProtection'   = @{ fn = 'Invoke-Control-LSAProtection'; level = 1 }
    'InteractiveLogon' = @{ fn = 'Invoke-Control-InteractiveLogon'; level = 1 }
    'RDP'             = @{ fn = 'Invoke-Control-RDP'; level = 1 }
    'CredentialGuard' = @{ fn = 'Invoke-Control-CredentialGuard'; level = 2 }
    'WSH'             = @{ fn = 'Invoke-Control-WSH'; level = 2 }
    'BitLocker'       = @{ fn = 'Invoke-Control-BitLocker'; level = 1 }  # gated by -EnableBitLocker
}

function Show-ControlList {
    Write-Host "`nAvailable control families:`n" -ForegroundColor White
    foreach ($name in $script:ControlTable.Keys) {
        Write-Host ("  {0,-18} (Level {1})" -f $name, $script:ControlTable[$name].level)
    }
    Write-Host "`nDestructive/opt-in controls also require a switch:" -ForegroundColor Yellow
    Write-Host "  BitLocker        -> -EnableBitLocker"
    Write-Host "  CredentialGuard  -> -EnableCredentialGuard"
    Write-Host "  RDP (disable)    -> -DisableRDP  (otherwise RDP is only hardened if already on)`n"
}

function Write-Summary {
    $g = $script:Results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host " SysRecon Hardening summary" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host (" Host      : {0}" -f $env:COMPUTERNAME)
    Write-Host (" OS        : {0} (build {1})" -f $script:Os.Caption, $script:Os.Build)
    Write-Host (" Level     : {0}" -f $Level)
    Write-Host (" Mode      : {0}" -f $(if ($script:PreviewOnly) { 'PREVIEW (no changes made)' } else { 'APPLY' }))
    Write-Host (" Results   : {0}" -f ($g -join '  '))
    if ($script:BundleDir) { Write-Host (" Backup    : {0}" -f $script:BundleDir) }
    if ($script:RebootRequired -and -not $script:PreviewOnly) {
        Write-Host " REBOOT REQUIRED for some controls to take effect." -ForegroundColor Yellow
    }
    if ($script:PreviewOnly) {
        Write-Host "`n This was a preview. Re-run with -Apply to make these changes." -ForegroundColor Cyan
    }
    else {
        Write-Host "`n Re-run sysrecon.exe to confirm findings are cleared." -ForegroundColor Cyan
        if ($script:BundleDir) {
            Write-Host (" Rollback with: .\Invoke-SysReconHardening.ps1 -Rollback '{0}'" -f $script:BundleDir)
        }
    }
    Write-Host ""

    # Machine-readable report next to the bundle.
    if ($script:BundleDir) {
        $script:Results | ConvertTo-Json -Depth 4 |
            Set-Content -Path (Join-Path $script:BundleDir 'results.json') -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    if ($ListControls) { Show-ControlList; return }

    $script:Os = Get-OsProfile
    Write-HardenLog ("SysRecon hardening on {0} ({1}, build {2})" -f $env:COMPUTERNAME, $script:Os.Caption, $script:Os.Build) 'INFO'

    if ($Rollback) {
        $log = Join-Path $Rollback 'rollback-transcript.log'
        try { Start-Transcript -Path $log -Append -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose $_.Exception.Message }
        Invoke-Rollback -Path $Rollback
        try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message }
        return
    }

    if ($script:Os.IsServer) {
        Write-HardenLog "This host reports as a Server/DC. The baseline targets workstations; some controls may not fit server roles. Review docs/HARDENING.md." 'WARN'
    }

    # Decide which controls run.
    $selected = foreach ($name in $script:ControlTable.Keys) {
        $c = $script:ControlTable[$name]
        if ($Include -and ($Include -notcontains $name)) { continue }
        if (-not $Include -and $c.level -gt $Level) { continue }
        if ($Exclude -and ($Exclude -contains $name)) { continue }
        $name
    }
    if ($EnableBitLocker -and $selected -notcontains 'BitLocker') { $selected += 'BitLocker' }
    Write-HardenLog ("Controls selected: {0}" -f ($selected -join ', ')) 'INFO'

    # Backup only when we intend to change something.
    if (-not $script:PreviewOnly) {
        New-BackupBundle
        if (-not $LogPath) { $LogPath = Join-Path $script:BundleDir 'transcript.log' }
        try { Start-Transcript -Path $LogPath -Append -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose $_.Exception.Message }
    }
    else {
        Write-HardenLog 'PREVIEW mode: evaluating controls, no changes and no backup.' 'INFO'
    }

    foreach ($name in $selected) {
        Write-HardenLog "--- $name ---" 'INFO'
        & $script:ControlTable[$name].fn
    }

    Write-Summary
    if (-not $script:PreviewOnly) { try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message } }
}
catch {
    Write-HardenLog "Fatal: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message }
    exit 1
}
