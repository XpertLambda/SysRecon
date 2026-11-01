# Changelog

All notable changes to SysRecon are documented here.

## [Unreleased]

### Fixed

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

### Known limitations

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
