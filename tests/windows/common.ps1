# Shared helpers for the Windows end-to-end tests. Dot-source after setting
# $OutDir (and optionally $script:TestTitle):
#
#     . (Join-Path $PSScriptRoot 'common.ps1')

$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:LastName = $null
if (-not (Get-Variable -Name TestTitle -Scope Script -ErrorAction SilentlyContinue)) {
    $script:TestTitle = 'SysRecon Windows test'
}

# On GitHub Actions, failures are also emitted as workflow annotations: they
# show on the run page and are readable through the public API, whereas the
# raw job log needs an authenticated download.
function Write-Annotation([ValidateSet('error', 'warning')][string]$Level, [string]$Message) {
    if (-not $env:GITHUB_ACTIONS) { return }
    $escaped = $Message.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host "::$Level title=$($script:TestTitle)::$escaped"
}
function Write-Step([string]$Title) {
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Assert-True([bool]$Condition, [string]$What) {
    if ($Condition) {
        Write-Host "  [PASS] $What" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $What" -ForegroundColor Red
        $script:Failures.Add($What)
        $context = if ($script:LastName) { Get-Tail $script:LastName } else { '' }
        if ($context) { Write-Host ($context -replace '(?m)^', '         | ') }
        Write-Annotation error ($(if ($context) { "$What`n--- last output of '$($script:LastName)' ---`n$context" } else { $What }))
    }
}

# Runs a process with a hard timeout and returns its exit code. stdout and
# stderr go to <OutDir>\<Name>.out.txt / .err.txt.
function Invoke-Timed {
    param(
        [Parameter(Mandatory)][string]$File,
        [string]$Arguments = '',
        [int]$TimeoutSec = 300,
        [string]$WorkingDirectory = $OutDir,
        [Parameter(Mandatory)][string]$Name,
        [string]$StdinFile
    )
    $start = @{
        FilePath               = $File
        WorkingDirectory       = $WorkingDirectory
        PassThru               = $true
        NoNewWindow            = $true
        RedirectStandardOutput = (Join-Path $OutDir "$Name.out.txt")
        RedirectStandardError  = (Join-Path $OutDir "$Name.err.txt")
    }
    if ($Arguments) { $start.ArgumentList = $Arguments }
    if ($StdinFile) { $start.RedirectStandardInput = $StdinFile }

    $p = Start-Process @start
    $null = $p.Handle  # Caches the handle so ExitCode is available afterwards.
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        $p.Kill($true)
        throw "$Name did not finish within $TimeoutSec s (hung)"
    }
    $p.WaitForExit()
    $script:LastName = $Name
    return $p.ExitCode
}

# Last lines of a step's stdout+stderr, for failure messages.
function Get-Tail([string]$Name, [int]$Lines = 8) {
    $text = @()
    foreach ($ext in 'out', 'err') {
        $f = Join-Path $OutDir "$Name.$ext.txt"
        if (Test-Path -LiteralPath $f) { $text += Get-Content -LiteralPath $f -Tail $Lines }
    }
    return ($text | Where-Object { $_ -and $_.Trim() }) -join "`n"
}

function Get-Output([string]$Name) {
    Get-Content -Raw -LiteralPath (Join-Path $OutDir "$Name.out.txt") -ErrorAction SilentlyContinue
}


# Prints the failure list and exits 1 if anything failed.
function Complete-Test {
    Write-Host ''
    if ($script:Failures.Count -gt 0) {
        Write-Host "$($script:Failures.Count) check(s) failed:" -ForegroundColor Red
        $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "Logs: $OutDir"
        exit 1
    }
    Write-Host 'All checks passed.' -ForegroundColor Green
    Write-Host "Logs: $OutDir"
    exit 0
}
