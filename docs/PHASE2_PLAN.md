# SysRecon Phase 2 — Penetration-Testing Assessment Plan

## Goal

Evolve SysRecon from a passive inventory/audit tool into a focused assessment
aid for **authorised** penetration testers and blue-teamers working on Windows
hosts. The tool must not only surface weaknesses but tell the operator exactly
how to fix each one. SysRecon stays **read-only**: it enumerates and evaluates,
it never modifies the target or executes exploit payloads.

## Principles

1. **Detection + remediation together.** Every finding carries a remediation
   step and a MITRE ATT&CK (or vendor) reference.
2. **Read-only and safe.** No configuration changes, no process injection, no
   credential dumping, no persistence. The tool reports what an attacker with
   the current token *could* abuse.
3. **Signal over noise.** Known-good system components are whitelisted; findings
   are ranked by severity and confidence.
4. **Actionable output.** Reports lead with an executive summary and a weighted
   risk score, then list findings most-severe first.

## Work completed in 2.0.0

### Core wiring finished (Phase 1 gaps)
- `--quick` now runs the essential-checks subset (`RunQuickScan`); previously it
  was parsed but ignored and always ran a full scan.
- `--stealth` is now applied to the engine (suppresses console logging).
- Config files are loaded and their per-module enable flags applied to the
  engine (the previous `// TODO: load config` is implemented).
- `SystemInfo` is fully populated (OS build, CPU, RAM, uptime, domain) and the
  report version string reflects the real build version.
- Process, Network (shares/firewall/ports/connections) and Registry
  (permissions/custom keys) modules now emit findings — previously they
  enumerated data but produced no report entries.

### Privilege-escalation module (`--privesc`)
Read-only checks, each with remediation + ATT&CK reference:

| Check | Technique | Severity |
|-------|-----------|----------|
| Unquoted service paths (writable prefix) | T1574.009 | High |
| Weak service DACLs (change-config to non-admins) | T1543.003 | High/Critical |
| World-writable service binaries/dirs | T1574.010 | High/Critical |
| `AlwaysInstallElevated` (HKLM+HKCU) | T1548.002 | Critical |
| Writable `PATH` directories | T1574.007 | High |
| Autorun targets writable by non-admins | T1547.001 | Medium/High |
| Cleartext autologon credentials | T1552.002 | High |
| UAC posture (`EnableLUA`, token filter) | T1548.002 / T1550.002 | Medium/High |
| Leftover unattend/sysprep answer files | T1552.001 | Medium |

Shared primitive: `Utils::IsWritableByNonAdmin()` evaluates an NTFS object's
DACL for write/modify access granted to Everyone / Authenticated Users / Users /
Interactive, and `Utils::ExtractExecutablePath()` safely parses service
`ImagePath` strings (quoted, unquoted-with-spaces, native prefixes).

### Reporting upgrades
- First-class `remediation` and `reference` fields in JSON.
- Remediation + Reference columns in CSV (with quote escaping).
- HTML report gained an executive summary, a weighted risk score (0–100) with a
  rating, severity-ranked findings, and a highlighted remediation box per
  finding. System facts (CPU/RAM/uptime/domain) are shown.

## Roadmap (candidate follow-ups, not yet implemented)

- Authenticode signature verification (`WinVerifyTrust`) for services, processes
  and autoruns to flag unsigned/invalidly-signed binaries.
- Scheduled-task actions review (writable task binaries, SYSTEM tasks).
- Token privilege review (`SeImpersonatePrivilege`, `SeBackupPrivilege`, …).
- Credential-store hints: DPAPI, saved RDP/WiFi profiles, `cmdkey` targets
  (presence only; no secret extraction).
- Patch-level / missing-KB correlation for known LPE CVEs.
- Named-pipe and COM/DCOM permission review.
- SARIF export for pipeline ingestion.

## Out of scope (by policy)

Exploit execution, payload generation, credential theft/exfiltration, lateral
movement, persistence installation, log tampering, and detection evasion.
SysRecon reports and recommends; it does not weaponise.
