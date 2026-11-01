#Requires -Version 7
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    End-to-end test of the audit -> remediate -> re-audit -> rollback loop.

.DESCRIPTION
    Runs hardening/Invoke-SysReconHardening.ps1 for real and uses sysrecon.exe
    to check the result, exactly as docs/HARDENING.md tells an operator to:

      1. audit                 sysrecon.exe
      2. preview               must change nothing
      3. -Apply                no control may fail; a backup bundle is written
      4. re-audit              the account-policy and firewall findings the
                               hardening addresses must be gone
      5. -Apply again          idempotency: must report zero changes
      6. -Rollback, re-audit   those findings must be back as in step 1

    Windows PowerShell 5.1 (powershell.exe) runs the hardening script, since
    that is the in-box shell it targets.

    THIS CHANGES SYSTEM SECURITY SETTINGS. It is meant for the disposable
    GitHub runner or a throwaway VM snapshot -- never a machine you care about.

.PARAMETER SysRecon
    Path to sysrecon.exe (with config.json beside it).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SysRecon,
    [string]$HardeningScript = (Join-Path $PSScriptRoot '..\..\hardening\Invoke-SysReconHardening.ps1'),
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) 'sysrecon-hardening-test')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SysRecon = (Resolve-Path -LiteralPath $SysRecon).Path
$HardeningScript = (Resolve-Path -LiteralPath $HardeningScript).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Bundles = Join-Path $OutDir 'bundles'

$script:TestTitle = 'SysRecon hardening loop test'
. (Join-Path $PSScriptRoot 'common.ps1')

trap {
    Write-Annotation error "Aborted: $($_.Exception.Message)"
    break
}

# Modules whose findings the hardening script is expected to clear.
$PolicyModules = @('Account Policy', 'Firewall')

# Runs a SysRecon audit and returns its findings for the policy modules as
# "module | item | risk" strings.
function Invoke-Audit([string]$Name) {
    $dir = Join-Path $OutDir $Name
    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
    $code = Invoke-Timed -File $SysRecon -Arguments "--accounts --network -f json -o `"$dir`"" -TimeoutSec 600 -Name $Name
    Assert-True ($code -eq 0) "$Name exits 0 (got $code)"
    $json = Get-ChildItem -LiteralPath $dir -Filter 'scan_*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    Assert-True ($null -ne $json) "$Name produced a report"
    if ($null -eq $json) { return @() }
    $report = Get-Content -Raw -LiteralPath $json.FullName | ConvertFrom-Json
    $incomplete = @($report.incomplete_checks)
    Assert-True ($incomplete.Count -eq 0) "$Name has no incomplete checks"
    foreach ($note in $incomplete) { Write-Annotation warning "$Name incomplete check: $note" }

    # Every Account Policy finding counts (the hardening also fixes the Low
    # ones: max age, history). The Low Firewall entry is the informational
    # "running with all profiles enabled" summary, not a finding.
    $findings = @($report.results |
        Where-Object { $PolicyModules -contains $_.module -and
                       -not ($_.module -eq 'Firewall' -and $_.risk_level -eq 'Low') } |
        ForEach-Object { "$($_.module) | $($_.item) | $($_.risk_level)" } |
        Sort-Object -Unique)
    Write-Host "  $Name policy findings ($($findings.Count)):"
    $findings | ForEach-Object { Write-Host "    - $_" }
    return , $findings
}

# Runs the hardening script under Windows PowerShell and returns its result
# counts parsed from the summary line ("Results   : Compliant=3  Changed=12").
function Invoke-Hardening([string]$Name, [string]$Arguments) {
    $cmd = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$HardeningScript`" -BackupPath `"$Bundles`" $Arguments"
    $code = Invoke-Timed -File 'powershell.exe' -Arguments $cmd -TimeoutSec 1200 -Name $Name
    Assert-True ($code -eq 0) "$Name exits 0 (got $code)"

    $out = Get-Output $Name
    $counts = @{ Compliant = 0; WouldChange = 0; Changed = 0; Skipped = 0; Failed = 0 }
    if ($out -and $out -match 'Results\s*:\s*(.+)') {
        foreach ($pair in ($Matches[1].Trim() -split '\s+')) {
            $kv = $pair -split '='
            if ($kv.Count -eq 2) { $counts[$kv[0]] = [int]$kv[1] }
        }
    }
    Write-Host ("  {0}: {1}" -f $Name, (($counts.GetEnumerator() | Sort-Object Name |
        ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '))

    # Surface every failed control individually.
    if ($out) {
        foreach ($line in ($out -split "`r?`n" | Where-Object { $_ -match '\[ERROR \]' })) {
            Write-Annotation error "$Name : $($line.Trim())"
        }
    }
    return $counts
}

function Get-NewestBundle {
    Get-ChildItem -LiteralPath $Bundles -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
}

function Compare-Findings([string[]]$Expected, [string[]]$Actual, [string]$What) {
    $diff = @(Compare-Object -ReferenceObject @($Expected) -DifferenceObject @($Actual) -ErrorAction SilentlyContinue)
    Assert-True ($diff.Count -eq 0) $What
    foreach ($d in $diff) {
        $side = if ($d.SideIndicator -eq '<=') { 'missing' } else { 'unexpected' }
        Write-Annotation warning "$What -- $side : $($d.InputObject)"
    }
}

# ---------------------------------------------------------------------------
Write-Step '1. Baseline audit'
$before = Invoke-Audit 'audit-before'
Assert-True ($before.Count -gt 0) 'baseline host has policy findings to remediate (test is meaningful)'

Write-Step '2. Preview changes nothing'
$preview = Invoke-Hardening 'harden-preview' ''
Assert-True ($preview.Failed -eq 0) "preview: no control failed to evaluate ($($preview.Failed) failed)"
Assert-True ($preview.WouldChange -gt 0) 'preview: proposes changes on an unhardened host'
Assert-True ($null -eq (Get-NewestBundle)) 'preview: wrote no backup bundle'
$afterPreview = Invoke-Audit 'audit-after-preview'
Compare-Findings $before $afterPreview 'preview left the audit findings unchanged'

Write-Step '3. Apply'
$apply = Invoke-Hardening 'harden-apply' '-Apply'
Assert-True ($apply.Failed -eq 0) "apply: no control failed ($($apply.Failed) failed)"
Assert-True ($apply.Changed -gt 0) 'apply: made changes'
$bundle = Get-NewestBundle
Assert-True ($null -ne $bundle) 'apply: wrote a backup bundle'
if ($bundle) {
    foreach ($f in 'results.json', 'secpol-before.inf', 'manifest.json', 'registry') {
        Assert-True (Test-Path -LiteralPath (Join-Path $bundle.FullName $f)) "bundle contains $f"
    }
    $resultsFile = Join-Path $bundle.FullName 'results.json'
    if (Test-Path -LiteralPath $resultsFile) {
        foreach ($r in @(Get-Content -Raw -LiteralPath $resultsFile | ConvertFrom-Json | Where-Object Status -eq 'Failed')) {
            Write-Annotation error "apply failed: $($r.Control) / $($r.Setting): $($r.Note)"
        }
    }
}

Write-Step '4. Re-audit: remediated findings are gone'
$afterApply = Invoke-Audit 'audit-after-apply'
Assert-True ($afterApply.Count -eq 0) "re-audit: no account-policy or firewall findings remain ($($afterApply.Count) left)"
foreach ($f in $afterApply) { Write-Annotation warning "still present after -Apply: $f" }

Write-Step '5. Second apply is idempotent'
$apply2 = Invoke-Hardening 'harden-apply-again' '-Apply'
Assert-True ($apply2.Failed -eq 0) "second apply: no control failed ($($apply2.Failed) failed)"
Assert-True ($apply2.Changed -eq 0) "second apply: zero changes ($($apply2.Changed) changed)"
$bundle2 = Get-NewestBundle
if ($bundle2 -and $bundle -and $bundle2.FullName -ne $bundle.FullName) {
    $results2 = Join-Path $bundle2.FullName 'results.json'
    if (Test-Path -LiteralPath $results2) {
        foreach ($r in @(Get-Content -Raw -LiteralPath $results2 | ConvertFrom-Json | Where-Object Status -eq 'Changed')) {
            Write-Annotation warning "not idempotent: $($r.Control) / $($r.Setting): '$($r.Current)' -> '$($r.Desired)'"
        }
    }
}

Write-Step '6. Rollback restores the original state'
if ($bundle) {
    $rb = Invoke-Timed -File 'powershell.exe' -Arguments "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$HardeningScript`" -Rollback `"$($bundle.FullName)`"" -TimeoutSec 600 -Name 'harden-rollback'
    Assert-True ($rb -eq 0) "rollback exits 0 (got $rb)"
    $afterRollback = Invoke-Audit 'audit-after-rollback'
    Compare-Findings $before $afterRollback 'rollback restored the original findings'
}

Complete-Test
