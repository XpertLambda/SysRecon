# Changelog

All notable changes to SysRecon are documented here.

## [Unreleased]

## [1.8.0] — 2026-11-02

### Added

- **Event Logs module** (`--eventlogs`, on by default; `modules.event_logs` in
  `config.json` with `lookback_days` and `failed_logon_threshold`). Read-only
  review of the Security, System and Defender logs:
  - disabled logs and logs smaller than the CIS sizes (Group Policy `MaxSize`
    honoured);
  - cleared logs (1102 / 104) and who cleared them;
  - new services (7045): command-interpreter / script-host services are High,
    binaries in user-writable locations or on shares Medium;
  - accounts created (4720) and added to privileged groups
    (4728 / 4732 / 4756);
  - failed-logon volume (4625) with top accounts and sources;
  - Defender detections (1116) and real-time protection turned off (5001).
  Event XML is parsed by portable, unit-tested functions
  (`Core::Text::XmlElementText`, `EventDataValue`, `XmlAttribute`,
  `ServiceInstallSeverity`, `IsPrivilegedGroupSid`).
- **Finding IDs**: every finding has a stable `<module>/<item>` ID (`id` in
  JSON, `ID` column in CSV, SARIF `ruleId`).
- **`--only` / `--skip`** filter findings by ID with `*` / `?` wildcards; a
  pattern without `/` matches the module.
- **`--baseline report.json`** compares with an earlier JSON report (any
  version): each finding is marked new or unchanged, and JSON/HTML reports list
  resolved findings. **`--new-only`** reports only new findings; with
  `--exit-code` it fails a pipeline only on regressions.
- **Network**: firewall rules are reviewed through `INetFwPolicy2`; an enabled
  inbound allow rule open to any address on any port for any program (and not
  scoped to a Store-app package) is High,
  and remote-administration / file-sharing ports open to any address on the
  Public profile are Medium. Listening ports name the service(s) hosted by the
  owning process.
- Interactive menu: Event Logs in the module selection.
- Windows end-to-end test covers the Event Logs module, `--only`, `--skip`,
  `--baseline` and `--new-only`, and publishes the Event Logs finding profile
  of a clean CI host. 133 unit tests (was 113).

### Changed

- SARIF `ruleId`s are the new finding IDs instead of raw module/item text.
- CSV reports have a trailing `ID` column.
- `--all` now also runs the Event Logs module (still not Domain).
- A config with only Event Logs or Domain enabled is valid.

## [1.7.1] — 2026-11-02

### Fixed — found by the Windows CI jobs on real Windows

- **~260 false Critical "weak service permissions" findings on a clean
  Windows install.** The service DACL check tested `mask & SERVICE_ALL_ACCESS`,
  which is non-zero for *any* service right, so the read/query access every
  standard service grants to Authenticated Users and INTERACTIVE counted as
  reconfiguration rights; most services run as LocalSystem, hence Critical.
  Only SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER and GENERIC_WRITE/ALL now
  count.
- **Writable-file/directory checks** (service binaries, PATH directories,
  autorun and scheduled-task targets) counted inherit-only ACEs, which grant
  nothing on the object itself, and treated attribute/EA writes and DELETE
  alone as "can replace". Both DACL decisions are now portable, unit-tested
  functions (`Core::Text::GrantsServiceReconfiguration`,
  `GrantsFileModification`, `AceAppliesToObject`).
- **Hardening audit-policy controls re-applied on every `-Apply`**:
  `Invoke-Native` returned its output with `return , $output`, which keeps the
  array as one pipeline object that neither piping nor `@(...)` unwraps, so
  `Select-String` saw every `auditpol` line joined into one string. It now
  returns the lines normally.
- **Defender reported as masquerading malware**: `MsMpEng.exe` / `NisSrv.exe`
  run from `C:\ProgramData\Microsoft\Windows Defender\Platform\<version>`
  after platform updates, which was not a trusted path (High, T1036.005, on
  every up-to-date host).
- **Visual C++ runtime DLLs reported as DLL side-loading**: `vcruntime140.dll`
  and `msvcp140.dll` were on the core-system-DLL list, but applications ship
  them app-local by design.
- The Windows end-to-end test hardcoded the default module list and failed
  once Privilege Escalation became default-on; it now derives the expected
  list from the installed `config.json`.

### Added

- The Windows end-to-end test publishes the Critical/High finding profile of a
  clean CI host as an annotation, and fails if a clean host produces more than
  10 Critical findings, so false-positive floods cannot recur silently.
- Unit tests for the DACL decisions (using real default Windows masks) and for
  the Defender-platform and VC++-runtime whitelist fixes (113 tests total).

### Changed

- README version, installer filenames and test counts were still those of
  1.2.0; they now match this release. `HANDOFF.md` rewritten for the current
  state (real-Windows CI, how to read its public annotations, backlog).

## [1.7.0] — 2026-11-02

### Added — light Active Directory domain reconnaissance (`--domain`, opt-in)

- New **Domain** module (`modules/domain/`), off by default and gated behind
  `--domain` / `modules.domain.enabled`. It only acts on a domain-joined host
  and performs standard read-only directory lookups any domain user can make:
  - domain / domain-controller / forest (via `DsGetDcNameW`);
  - the domain **password and lockout policy** (`NetUserModalsGet`), flagging a
    minimum length below 14, non-expiring passwords, and disabled lockout;
  - **Domain Admins** membership (`NetGroupGetUsers`), flagged when the group is
    large (big privileged blast radius);
  - **domain trusts** (`DsEnumerateDomainTrustsW`), with direction.
- Each finding carries remediation and a MITRE ATT&CK / CIS reference. On a
  standalone/workgroup host the module does nothing.

> Read-only situational awareness only: it never authenticates elsewhere,
> modifies the directory, or requests credentials.

## [1.6.0] — 2026-11-02

### Added — Tier 4 pen-tester workflow / output

- **`--min-severity low|medium|high|critical`**: drops findings below the given
  severity from the collected results and from every report format.
- **`--exit-code`**: the process exit code reflects the highest finding severity
  (none/low `0`, medium `10`, high `20`, critical `30`); a report-generation
  failure is `2`. Off by default so existing/interactive behaviour is unchanged.
- **SARIF 2.1.0 output** (`-f sarif`): one rule per finding type, ATT&CK
  technique IDs as rule tags, `security-severity` for code-scanning dashboards.
- **MITRE ATT&CK Navigator layer** (`-f navigator`): techniques parsed from each
  finding's reference, coloured/scored by severity — drop straight into
  Navigator.
- **Risk score**: the previously-stubbed weighted 0-100 score and rating
  (Minimal…Critical) are computed and shown in the JSON summary and the HTML
  report.

New portable, unit-tested helpers `ParseSeverity` and `SeverityExitCode`
(105 tests total).

## [1.5.0] — 2026-11-02

### Added — Tier 2 credential & hardening-posture detections (`--privesc`)

- **Credential exposure** (`check_credentials`, presence/paths only — no secret
  value is ever read): WDigest `UseLogonCredential`, LSASS protection
  (`RunAsPPL`), Credential Guard (`LsaCfgFlags`), and the presence of common
  secret-bearing artefacts (PowerShell `ConsoleHost_history.txt`, `.aws`/
  `.azure`/`.kube`, DPAPI/Credential Manager store).
- **Defender posture** (`check_defender`): Defender disabled-by-policy, and the
  **exclusion Paths/Processes/Extensions** and Tamper-Protection state read from
  the Defender and policy registry keys. Exclusions are prime attacker intel and
  are surfaced for review.
- **Hardening baseline** (`check_hardening`): detection counterparts to
  `hardening/Invoke-SysReconHardening.ps1` — SMBv1 server, SMB signing,
  LLMNR, LM/NTLMv1 (`LmCompatibilityLevel`), PowerShell Script Block logging,
  and LAPS presence. Each finding cites the matching CIS control, so the audit
  flags exactly what the companion script remediates.

New `modules.privesc.*` config flags: `check_defender`, `check_hardening`.

## [1.4.0] — 2026-11-01

### Added — Tier 1 local-privilege-escalation checks (`--privesc`)

- **Current security context** (`check_tokens`): reports the process integrity
  level and elevation, and raises a finding for each sensitive privilege held
  by the token — `SeImpersonate`/`SeAssignPrimaryToken` (Potato family, T1134),
  `SeBackup`/`SeRestore`/`SeTakeOwnership`/`SeDebug`/`SeLoadDriver`/
  `SeManageVolume`/`SeTcb` — each with its abuse path and remediation.
- **Authenticode verification + SHA-256** (`verify_signatures`): writable
  service-binary, autorun, scheduled-task and extended-autostart findings now
  carry the binary's signature status (signed/unsigned/untrusted, with signer)
  and SHA-256, for triage and IOC lookups. `Utils::VerifySignature`
  (`WinVerifyTrust`) + a portable, unit-tested `Utils::CalculateSHA256`.
- **Scheduled tasks** (`check_scheduled_tasks`): enumerates tasks via the Task
  Scheduler COM API and flags any that run with highest/SYSTEM rights whose
  action binary or its directory is writable by a non-admin (T1053.005).
- **Extended autostart / DLL-hijack surface**: Winlogon `Userinit`/`Shell`/
  `Taskman`, `AppInit_DLLs` (+ WOW6432Node) and IFEO `Debugger` entries whose
  target is writable by a non-admin (T1547.004 / T1546.010 / T1546.012).
- **Missing-patch hints** (`check_patches`): enumerates installed hotfixes via
  WMI (`Win32_QuickFixEngineering`) and flags well-known LPE CVEs
  (PrintNightmare, HiveNightmare/SeriousSAM, CVE-2021-1732/2022-21882,
  Zerologon) whose fixing KB is absent. Marked "potential / verify" because
  cumulative updates can supersede the listed KBs. The comparison table is a
  portable, unit-tested `Utils::MissingLpePatchHints`.

New `modules.privesc.*` config flags: `verify_signatures`, `check_tokens`,
`check_scheduled_tasks`, `check_patches`. New unit tests cover the SHA-256 NIST
vectors, `ExtractExecutablePath`, and the patch-hint table (103 tests total).

## [1.3.0] — 2026-11-01

### Added

- **Privilege-escalation assessment module (`--privesc`, on by default).** A
  read-only, host-local pass for the local LPE and misconfiguration vectors an
  authorised pen-tester checks first. Every finding carries a concrete
  remediation step and a MITRE ATT&CK reference:
  - unquoted service paths with a hijackable prefix (T1574.009);
  - weak service DACLs granting reconfiguration rights to non-admins (T1543.003);
  - world-writable service binaries / directories run as SYSTEM (T1574.010);
  - `AlwaysInstallElevated` set in both HKLM and HKCU (T1548.002);
  - writable directories on `%PATH%` enabling binary/DLL planting (T1574.007);
  - autorun targets writable by non-admins (T1547.001);
  - cleartext autologon credentials in the registry (T1552.002);
  - UAC posture: `EnableLUA`, `LocalAccountTokenFilterPolicy` (T1548.002 / T1550.002);
  - leftover unattended-install answer files (T1552.001).
  Category toggles are exposed under `modules.privesc.*` in `config.json`.
- **Remediation and reference are now first-class report fields.** JSON gains
  `remediation`/`reference` per result; CSV gains Remediation and Reference
  columns; HTML renders a highlighted remediation box and a reference line per
  finding. Findings from other modules are unaffected (fields stay empty).
- Shared helpers `Utils::IsWritableByNonAdmin` (DACL check that honours DENY
  ACEs) and `Utils::ExtractExecutablePath` (quoting-aware ImagePath parser),
  the latter unit-tested in `sysrecon_core`.

## [1.2.0] — 2026-11-01

### Fixed

- **The hardening script failed on Windows PowerShell 5.1, its in-box target**
  (found by its first real run, in the new `hardening-test` CI job):
  - every `-Apply` aborted during backup, before changing anything: the
    audit-policy backup passed `/file:(Join-Path ...)` to `auditpol`
    literally, and its error became a terminating error;
  - every `-Rollback` aborted on `reg.exe import`, which writes "The operation
    completed successfully." to stderr. Under 5.1 with
    `$ErrorActionPreference = 'Stop'`, redirected native stderr is a
    terminating error;
  - `net accounts`, `secedit` and `auditpol` changes were recorded as
    "Changed" without checking the exit code;
  - account-lockout settings were applied in arbitrary (hashtable) order,
    though `net accounts` rejects a lockout window longer than the duration.

  All native tools now run through one helper that captures stderr and fails
  on a non-zero exit code. A backup failure aborts before any change; rollback
  attempts every step and exits non-zero if any could not be restored.
- **Hardening rollback did not restore most changes.** It re-imported
  whole-key `.reg` exports, which fails for `Lsa`, `Terminal Server` and
  `Winlogon` (protected subkeys), and never restored SMB server settings, the
  Guest account, Defender preferences or ASR rules at all. Every change is now
  recorded with its previous value in a `changes.json` undo journal, and
  rollback replays it exactly.
- **Hardening audit-policy controls re-applied on every run**: they read the
  "Exclusion Setting" column of `auditpol /r` (always empty) instead of
  "Inclusion Setting", so a second `-Apply` was never a no-op.
- **The Security event log size was set to 192 GB instead of 192 MB**: the
  policy value is in KB, and 201326592 (192 MB in bytes) was written. Now
  196608 KB, the CIS value.

- **Every run with command-line arguments crashed on real Windows** (access
  violation, exit code `0xC0000005`), including `--help`. `main()` forwarded
  `__wargv` to `wmain`, but without `-municode` the MinGW/UCRT startup only
  initialises the narrow `argv`, so `__wargv` was NULL. Wine initialises both,
  which is why every wine test passed. MinGW builds now use `-municode` and
  the CRT calls `wmain` directly. Found by the new Windows end-to-end CI job.
- **All console output was lost on real Windows when redirected** to a file or
  pipe (`sysrecon.exe --help > out.txt` gave an empty file). The CRT's
  locale-dependent wide-to-narrow conversion rejected the banner's box-drawing
  characters and the stream silently discarded everything after them. Output
  now goes straight to the handle: `WriteConsoleW` for a console, UTF-8 with
  CRLF line endings for files and pipes. Wine's CRT is more lenient, so only
  the Windows CI job caught this.

- **A module disabled in `config.json` could not be enabled from the command
  line.** Modules were constructed from the config selection *before* the
  command-line selection was applied, so `sysrecon.exe --memory` with the
  shipped config ran nothing and reported success. Selection is now resolved
  first (`src/core/scan_plan.cpp`) and the engine constructs exactly that set.
- **Without a config file, the Memory module ran by default.** The engine
  treated any module missing from its map as enabled. Built-in defaults now
  match the shipped config (Memory off).
- **The config was only looked up in the working directory**, so an installed
  copy run from an elevated prompt (which starts in System32) ran with no
  config at all. It is now also looked up next to `sysrecon.exe`, and a
  relative `output_directory` is resolved against the config file's folder.
- **Config options that were parsed and then ignored now take effect:**
  `processes.check_dlls`, `registry.scan_startup_keys` / `analyze_policies` /
  `check_permissions`, `network.scan_listening_ports` / `analyze_connections`,
  and `output.generate_json` / `generate_csv` / `generate_html` (used when no
  `-f` is given). `memory.analyze_heap` did nothing and has been removed.
- `config.json` from the file overrode `--verbose` and `--quiet`.
- An invalid config (wrong value type, failed validation) left a half-applied
  mixture of file values and defaults. Loading is now all-or-nothing; an
  existing but invalid config, or a missing `-c` file, aborts with the specific
  errors listed. Unknown or removed settings (`security.*`, `max_threads`, ...)
  are reported as warnings instead of being silently ignored.
- **Silent uninstall still hung**: the uninstaller's "Are you sure?" prompt in
  `un.onInit` had no silent default, so `Uninstall.exe /S` blocked before
  reaching the earlier `IfSilent` fixes.
- **"Add to PATH" did nothing** but print a hint. It now adds the install
  directory to the machine PATH (without NSIS's 1024-character string limit,
  which would have truncated long PATHs), and uninstall removes it again.
- An upgrade install overwrote the operator's edited `config.json`.
- The quick scan always reported zero listening ports: it never loaded the TCP
  table. Ports, connections and the firewall are now actually reported (the
  risk functions for ports and connections existed but were never called).
- The firewall check only looked at the MpsSvc service; a running service with
  a disabled profile was reported as "running". Each profile is now checked,
  with Group Policy values taking precedence.
- The registry policy reader read `REG_SZ` data without a bounds-checked
  terminator (same class as the Run-key crash fixed in 1.1.0).
- Interactive mode looped forever when stdin reached end of input
  (`sysrecon.exe < NUL`).
- Errors from one interactive scan were reported again by every later scan;
  modules from an earlier scan stayed alive and kept contributing to reports.
- HTML report header values (computer and user name) were not escaped.
- `build-installer.sh` / `.bat` generated a `config.json` in an obsolete format
  the binary cannot read, and a stand-in LICENSE with different terms. Both are
  tracked files; a missing one is now an error. `clean.sh` no longer hardcodes
  the version.
- CI ran only on `main`.

### Added

- **Account findings by RID**: the built-in Administrator (RID 500) and Guest
  (RID 501) are detected even when renamed, along with enabled accounts that
  may have an empty password (`UF_PASSWD_NOTREQD`). Administrators-group
  membership is resolved by well-known SID, so it works on localised Windows.
- **Password and lockout policy** check (minimum length, lockout threshold and
  duration, maximum age, history) against the CIS L1 values the hardening
  script applies, so audit → remediate → re-audit closes.
- Network findings for network-reachable services on commonly attacked ports
  and for established connections to common backdoor/C2 ports, with the owning
  process name; plus one inventory entry listing exposed TCP ports.
- `--all` (all six modules, including Memory). The README already documented
  it; it did not exist.
- Reports record the run context (elevated or not, modules, stealth mode,
  config file used) and an **Incomplete Checks** section listing every check
  that failed, in JSON, CSV and HTML. Findings are sorted by severity.
- End-of-scan console summary by severity, and scan duration.
- `sysrecon_core` now contains `Utils` (with a portable UTF-8 codec that
  replaces invalid input with U+FFFD), `Logger`, `ConfigManager` and the scan
  plan, so they are unit-tested natively; `tests/test_core.cpp` is built for the
  first time. 94 tests, up from 41, including the IPv4 parsing tests the 1.1.0
  entry claimed but that did not exist.
- CI builds the NSIS installer with warnings as errors, checks that interactive
  mode exits on EOF, and runs the parser and PSScriptAnalyzer over the
  hardening script on a Windows runner.
- **End-to-end Windows test** (`windows-test` CI job,
  `tests/windows/smoke-test.ps1`) on a real Windows runner: silent install,
  PATH, scans with no incomplete checks, config discovery from another
  directory, all report formats, quick/stealth/error paths, upgrade keeping
  `config.json`, and silent uninstall under a timeout. Covers the Windows APIs
  wine does not implement.
- Installer `/ADDTOPATH` switch, so an unattended `/S` install can select the
  default-off "Add to PATH" component.
- **Reports and the log file are access-restricted**: each gets a protected
  ACL granting access only to SYSTEM, Administrators and the file's owner. They
  previously inherited the folder's ACL, which under Program Files lets every
  local user read usernames, SIDs and admin membership.
- **Start Menu and desktop scan shortcuts request elevation** ("Run as
  administrator"). Their descriptions always said so, but nothing elevated, so
  a scan started from the Start Menu aborted on `require_admin`.
- When SysRecon owns its console window (started from a shortcut), it waits
  for a key before exiting so Quick Scan and Help output can be read.
- **Hardening loop test** (`hardening-test` CI job,
  `tests/windows/hardening-test.ps1`): audit, preview (must change nothing),
  `-Apply` (no control may fail), re-audit (account-policy and firewall
  findings must be gone), second `-Apply` (must change nothing), `-Rollback`
  (findings must return). The first real run of the hardening script.
- CI also builds and unit-tests with **MSVC**, runs the Windows end-to-end test
  on **Windows 11** (`windows-11-arm`, x64 emulation) as well as Windows
  Server 2022, and checks that release binaries keep DEP and ASLR enabled.
- `--version` reports the actual compiler instead of always "MinGW-w64".

- **Windows hardening companion.** `hardening/Invoke-SysReconHardening.ps1`
  applies a CIS Level 1 (workstation)-aligned baseline, closing the loop with
  the read-only audit tool (audit → remediate → re-audit). `sysrecon.exe`
  remains strictly read-only; this separate, opt-in, elevated script is the only
  component that writes to the OS. Safe on fresh and already-used installs:
  preview by default (no change without `-Apply`), full backup bundle +
  `-Rollback`, idempotent, and `-Level`/`-Include`/`-Exclude` scoping with
  destructive controls (BitLocker, RDP-disable, Credential Guard) behind
  explicit switches. Covers firewall, SMBv1/signing, UAC, legacy-auth, password
  & lockout policy, Guest account, Defender + 15 ASR rules, AutoRun, advanced
  audit policy, PowerShell logging, LSA protection, interactive-logon lockdown,
  and RDP hardening. Full catalogue and rollback runbook in
  `docs/HARDENING.md`.
- `hardening/PSScriptAnalyzerSettings.psd1` documenting the intentional linter
  exclusions.

### Changed

- README: new **Windows Hardening** section; the "Is SysRecon safe to run?" FAQ
  now distinguishes the read-only `sysrecon.exe` from the opt-in hardening
  script; Roadmap "Remediation Actions" / "Compliance Profiles" marked partially
  delivered (CIS L1 shipped).
- README corrected where it described behaviour the code does not have: Browser
  Helper Object and BitLocker checks (none exist), "Control Flow Guard:
  Enabled" (MinGW-w64 GCC does not emit CFG; DEP and ASLR are enabled), an
  invented JSON/CSV schema (now the real one), untested OS compatibility and
  scan-time figures, Windows APIs that are never called, and an MSI installer
  that does not exist.

### Known limitations

- The registry policy check for "Windows Defender disabled by policy"
  (`DisableAntiSpyware`) reads the wrong key and cannot fire; UAC is the only
  policy it reports.
- Release builds do not enable Control Flow Guard (toolchain limitation).
- **The memory module's malware scan still cannot report anything**:
  `ScanForMalware` iterates a per-process inventory that only
  `AnalyzeProcessMemory` fills, and nothing calls it. The RWX-region check and
  `CreateMemoryDump` are unreachable for the same reason, and
  `memory.create_dumps` has no effect. Unchanged in this revision.
- `--stealth` now has a defined meaning (no console log, no per-process DLL
  snapshots, no Memory module). It does not hide SysRecon from EDR.
- The hardening script is parsed and linted in CI, but has no behavioural tests
  and has **not** been run end-to-end on a live Windows host by us. Validate on a VM (fresh + used snapshots) per the
  checklist in `docs/HARDENING.md` before production use.

## [1.1.0] — 2026-07-16

This release is the outcome of a pre-delivery audit. The headline change is
honesty: SysRecon now does everything it claims, and no longer claims anything
it does not do. Several capabilities were removed rather than left in place
doing nothing — see **Removed** below.

### Fixed — blocking

- **All output was lost whenever it was redirected.** `sysrecon.exe --help >
  out.txt` produced a zero-byte file. When stdout is a file or pipe,
  `GetConsoleWindow()` returns NULL, so the startup path called `AllocConsole()`
  and reopened stdout onto an invisible console. The tool now attaches to the
  parent console and never reopens an already-redirected handle. A CI check
  asserts redirected output stays non-empty.
- **Silent uninstall hung forever.** NSIS shows a `MessageBox` even under `/S`
  unless guarded with `IfSilent`. `Uninstall.exe /S` deleted the binary and then
  blocked on "Do you want to delete all generated reports?", leaving a
  half-removed product. Silent install over an existing installation had the
  same defect.

### Fixed — security

- **Stored XSS in HTML reports.** Registry Run value names, service display
  names and process names were interpolated raw into the report — the one file
  an analyst is guaranteed to open. All untrusted values are now escaped.
- **CSV formula injection.** A value beginning `=`, `+`, `-` or `@` executed on
  open in Excel, so anyone able to name a service could attack the analyst's
  machine. Fields are now neutralised and quoted per RFC 4180 (embedded quotes
  were never doubled, which also corrupted every service path containing one).
  Reports now carry a UTF-8 BOM.
- **Whitelist evasions that suppressed findings entirely.** Each of these hid an
  implant from the report rather than merely misranking it:
  - `IsSystemPath` prefix-matched without a path boundary, so
    `C:\WindowsUpdate\evil.exe` counted as a Windows system path.
  - `IsKnownPersistenceKey` substring-matched the **attacker-chosen** Run value
    name, so an entry called `OneDrive Updater` whitelisted itself out of the
    report. It was also the only case-sensitive check, so `onedrive` bypassed it
    in the other direction.
  - `IsSystemProcess`/`Service`/`Dll` matched on name only, so an implant named
    `csrss.exe` was exempt from injection detection (MITRE T1036.005).
  - `IsSafeUnquotedPath` declared `C:\evil.exe "..."` safe and auto-trusted
    anything under `C:\Program Files\Windows*`.

  Suppression now always requires corroborating evidence that the referenced
  image actually lives in a system directory. Every case above has a regression
  test.
- **Attacker-reachable crash in the registry module.** Run-key values were read
  as wide strings without checking the value type, and the length computed as
  `size/2 - 1` underflowed to `SIZE_MAX` for an empty value.
- `EnableDebugPrivilege` reported success for non-administrators
  (`AdjustTokenPrivileges` returns TRUE even when it assigns nothing), and was
  only enabled as a side effect of the Accounts module — so `--processes` alone
  silently produced empty results.

### Fixed — detections that could never fire

- `DetectProcessHollowing` queried address 0, which is always free, so it could
  never return true. It now checks the process image base (T1055.012).
- `ScanMemoryRegion` called its PE-header and shellcode detectors and discarded
  both results into empty `if` bodies — the malware scan could never report
  anything.
- `AnalyzePermissions` fetched a security descriptor and never parsed it,
  emitting a Low "Accessible" for every key. It now reports keys writable by
  non-administrative principals (T1112). It and `ScanCustomKeys` were also never
  dispatched.
- `CreateMiniDump` created an empty file, logged "Memory dump created" and
  returned success having written zero bytes. It now calls `MiniDumpWriteDump`.
- **The Processes module produced no findings at all** while printing "Running
  Processes". It now detects masquerading (T1036.005) and DLL side-loading
  (T1574.002), and flags execution from user-writable locations.
- `EnumerateShares` and `AnalyzeFirewall` were fully implemented but never
  called, so the High "Firewall is disabled" finding was unreachable.
- HKCU Run keys were enumerated and then dropped without being reported.

### Fixed — false positives

- Any committed private executable region was reported as DLL injection — true
  of every .NET/Java/JS process that JITs code. Now requires a PE image in
  private memory.
- Image File Execution Options and Browser Helper Objects were flagged purely
  because the keys exist, which they do on every Windows install. IFEO now
  reports only an actual `Debugger` value (T1546.012); the BHO check is gone.
- Every non-`$` network share was reported High, because `shi2_permissions == 0`
  was read as "full access". That field only applied to share-level security and
  is always 0 on modern Windows.

### Fixed — correctness

- `config.json` was **entirely dead**: `main.cpp` had a `// TODO: Load config
  into engine` directly beneath a log line claiming the config was loaded. It now
  drives module selection, output directory, and per-module options.
- `--quick` was a no-op — `RunQuickScan()` existed and was never called, so the
  flag and the installer's Quick Scan shortcut silently ran a full scan.
- A single failing module discarded every other finding and produced no report.
  Failures are now recorded and surfaced while the scan exports what it found.
- Module steps were chained with `&&`, so one failure silently skipped the rest.
- `-o` created one directory while reports were written to another.
- Account timestamps decoded to ~3600 years in the past (`USER_INFO_3` times are
  Unix seconds, not FILETIME).
- File logging was never enabled, though the UI told users to "check the logs";
  the log also mangled all non-ASCII text by truncating each `wchar_t` to `char`.
- Data race in the logger; `std::localtime` replaced with `localtime_s`.
- Resource leaks: TCP table buffer, SCM handle on re-entry. Modules now clear
  state before re-enumeration (a second interactive scan doubled every result).
- Interactive menu: "Run Full System Scan" could silently run a *selective*
  scan, and deselecting every module still ran a zero-module scan reported as
  success.
- Memory-safety: unsigned underflow in the shellcode scanner, a strict-aliasing
  violation reading attacker-controlled memory, `std::wstring(nullptr, 0)` UB,
  uninitialised struct members reaching public results, addresses printed as
  decimal behind an `0x` prefix.

### Added

- **Tests.** 41 unit tests covering report escaping, whitelist matching, path
  handling and IPv4 parsing, with regression tests pinning every security issue
  above. Previously `tests/test_core.cpp` was compiled by no build system and
  gtest was not a dependency.
- **CI** (GitHub Actions): native unit tests, Windows cross-compile, and a
  smoke test asserting redirected output is not empty.
- `sysrecon_core`: platform-independent logic, unit-testable without wine.
- Operator-extensible whitelist (previously compile-time only, so every
  third-party service produced a finding).
- Findings now carry MITRE ATT&CK technique IDs.

### Changed

- CMake is the only build system. `Makefile` and `Makefile.linux` are deleted:
  neither compiled `modules/`, both pulled in placeholder stubs via a wildcard,
  and neither had `-Iexternal`, so neither could ever have built the project.
- Version is generated from a single source. The banner said 1.1.0 while reports
  and the installer said 1.0.0.
- `-mconsole` is gated behind MinGW so the MSVC build can link.
- `include(CPack)` moved after the `CPACK_*` variables it snapshots.
- Installer: components page added (four selectable sections and their
  descriptions were unreachable); `File` path corrected for POSIX `makensis`.
- README corrected throughout — see **Removed**. It had claimed unit,
  integration and regression tests plus performance benchmarks (none existed),
  documented `--threads`/`--timeout`/`--no-admin-check` (no such flags), and
  described a "thread pool architecture" that does not exist.

### Removed

Deliberately removed rather than left as settings and API that do nothing. All
are recorded in the README roadmap as future work.

- ~200 declared-but-undefined functions across every module header. An automated
  check now reports zero.
- `security.encrypt_output` / `sign_reports` / `encryption_key` /
  `signing_cert`: never implemented. `encrypt_output: true` produced an
  unencrypted report with no warning, and `encryption_key` sat in plaintext.
- `max_threads` / `timeout_seconds`: there is no threading and no timeout.
- `output.compress_output`: defaulted true, silently ignored.
- PDF, XML and plain-text reports: the latter two logged "Generating…" and then
  returned false without writing a byte.
- `src/modules_placeholder.cpp` and `_new.cpp`: duplicate stub symbols; `_new`
  did not even parse.

### Known limitations

- **SysRecon will likely trigger EDR.** The memory module reads other processes'
  memory, including `lsass.exe`. Coordinate before running it.
- **Reports are sensitive and unprotected** — SIDs, usernames, admin membership,
  service paths, MAC/IP addresses — written with default ACLs, not encrypted.
- The output directory is relative to the working directory; an elevated shell
  typically starts in `System32`.
- Modules run sequentially; no timeouts are enforced.
- The MSVC and native-MinGW builds are not covered by CI and are unverified.
- `tests/test_core.cpp` is still not built: it exercises `Utils` and `Logger`,
  which remain Win32-coupled. Splitting them into `sysrecon_core` is the
  follow-up.
- Full installer install/uninstall verification requires a Windows VM; NSIS
  uninstallers do not complete reliably under wine.
- Registry ACL analysis covers a fixed set of persistence-relevant keys.
- Findings are leads, not verdicts.

## [1.0.0]

Initial release.
