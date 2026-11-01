# PSScriptAnalyzer settings for the SysRecon hardening script.
#
# Run:  Invoke-ScriptAnalyzer -Path .\Invoke-SysReconHardening.ps1 -Settings .\PSScriptAnalyzerSettings.psd1
#
# The rules excluded below are deliberate design choices for THIS script, each
# justified. Every other rule (including all correctness rules) stays on.
@{
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # Interactive operator tool: coloured, human-readable console output is
        # the intended UX. Machine-readable output is emitted separately as
        # results.json, so Write-Host here is correct, not a smell.
        'PSAvoidUsingWriteHost',

        # The script implements a single global preview gate (-Apply, plus native
        # -WhatIf via SupportsShouldProcess on the script itself). Individual
        # internal setter helpers (Set-RegistryValue, Set-SecEditPolicy) honour
        # that gate rather than each re-declaring SupportsShouldProcess, which
        # would produce confusing nested -WhatIf semantics.
        'PSUseShouldProcessForStateChangingFunctions',

        # False positive: $BackupPath / $DisableRDP / $EnableCredentialGuard are
        # script-level params consumed inside nested control functions, which the
        # analyzer scopes separately and therefore reports as unused.
        'PSReviewUnusedParameter',

        # Naming convention: control families use the Invoke-Control-<Family>
        # pattern (BuiltinAccounts), where the family name is intentionally the
        # plural domain term.
        'PSUseSingularNouns'
    )
}
