# SysRecon Windows Hardening

`hardening/Invoke-SysReconHardening.ps1` applies a **CIS Level 1
(workstation)-aligned** security baseline to a Windows host. It is the
write-capable companion to SysRecon: `sysrecon.exe` audits (read-only, never
changes anything), and this script remediates.

> **Scope, stated honestly.** This is a pragmatic scripted subset of CIS L1 for
> a standalone / workgroup Windows workstation. It is **not** a replacement for
> the full CIS-CAT tooling, the Microsoft Security Baseline GPOs, or a domain
> GPO deployment, and it does not claim to secure "everything." It covers the
> high-value controls that SysRecon audits plus the surrounding CIS L1 set, each
> reversible and each documented below.

---

## The loop

```
sysrecon.exe                              # 1. audit  -> findings
Invoke-SysReconHardening.ps1              # 2. PREVIEW the fixes (changes nothing)
Invoke-SysReconHardening.ps1 -Apply       # 3. back up, then remediate
sysrecon.exe                              # 4. re-audit -> confirm findings cleared
```

## Requirements

- Windows 10 / 11 or Windows Server 2016+ (see per-edition notes below).
- An **elevated** PowerShell session (`#Requires -RunAsAdministrator`).
- PowerShell 5.1 (in-box) or PowerShell 7+.

## Safety model

This is the reason the script exists in this form. All four hold on both fresh
and already-used installations:

| Guarantee | How |
|---|---|
| **Preview by default** | Nothing changes without `-Apply`. The default run evaluates every control and prints the exact `current -> desired` change set. |
| **Reversible** | Before the first change, a timestamped bundle is written (registry exports, `secedit` template, `auditpol` backup, firewall export, service start types) and a System Restore point is attempted. Restore with `-Rollback <bundle>`. |
| **Idempotent** | Every control reads current state and writes only on drift. A second `-Apply` on a hardened host reports **zero** changes. |
| **Scoped / opt-in** | `-Level 1` (default) is built not to break normal use. `-Level 2` and the destructive controls are opt-in behind explicit switches. |

## Usage

```powershell
# Preview every CIS L1 change. Changes nothing.
.\Invoke-SysReconHardening.ps1

# Back up, then apply the CIS L1 baseline.
.\Invoke-SysReconHardening.ps1 -Apply

# Apply everything except two families.
.\Invoke-SysReconHardening.ps1 -Apply -Exclude Firewall,RDP

# Apply only two families.
.\Invoke-SysReconHardening.ps1 -Apply -Include SMB,Defender

# Include Level 2 controls.
.\Invoke-SysReconHardening.ps1 -Apply -Level 2

# List the control families and exit.
.\Invoke-SysReconHardening.ps1 -ListControls

# Roll back a previous run.
.\Invoke-SysReconHardening.ps1 -Rollback 'C:\ProgramData\SysRecon\hardening-backups\2026-07-16_14-05-32'
```

### Parameters

| Parameter | Meaning |
|---|---|
| `-Apply` | Make changes. Without it, preview only. |
| `-Level 1\|2` | Control depth. Default `1`. |
| `-Include <families>` | Run only these families (overrides `-Level`). |
| `-Exclude <families>` | Run the selected set except these. |
| `-ListControls` | Print families and exit. |
| `-Rollback <path>` | Restore a backup bundle and exit. |
| `-BackupPath <dir>` | Backup root. Default `%ProgramData%\SysRecon\hardening-backups`. |
| `-LogPath <file>` | Transcript path. Default inside the bundle. |
| `-EnableBitLocker` | Opt-in. Encrypt the OS volume (see the warning below). |
| `-DisableRDP` | Opt-in. Fully disable RDP (otherwise RDP is only *hardened* if already on). |
| `-EnableCredentialGuard` | Opt-in (L2). Enable VBS / Credential Guard. |

---

## Control catalogue

Every setting is idempotent and captured in the backup bundle. "Risk" is the
chance the control disrupts a normal workstation.

### Level 1 (default)

| Family | Setting | Target | CIS | Risk |
|---|---|---|---|---|
| **Firewall** | Domain/Private/Public profiles | Enabled, default-inbound Block, log dropped | 9.1–9.3 | Low |
| **SMB** | SMBv1 server protocol | Disabled | 18.3.1 | Low |
| | SMB signing (server + client) | Required | 2.3.8.1 / 2.3.9.x | Low |
| | Insecure guest logons | Denied | 18.5.x | Low |
| | SMB1 optional feature | Removed (**reboot**) | 18.3.1 | Low |
| **UAC** | EnableLUA / admin consent prompt / secure desktop / installer detection | On | 2.3.17.x | Medium |
| **LegacyAuth** | LmCompatibilityLevel | 5 (NTLMv2 only) | 2.3.11.7 | Medium |
| | NoLMHash | 1 | 2.3.11.5 | Low |
| | RestrictAnonymous / RestrictAnonymousSAM | 1 | 2.3.10.x | Low |
| | WDigest UseLogonCredential | 0 (no plaintext creds in LSASS) | — | Low |
| | LLMNR (multicast name resolution) | Disabled | 18.5.4.2 | Low |
| | NetBIOS node type | P-node (no NBT-NS broadcast) | — | Medium |
| **AccountPolicy** | Min password length | ≥ 14 | 1.1.4 | Low |
| | Password complexity | Enabled | 1.1.5 | Low |
| | Max / min password age | ≤ 365 / ≥ 1 | 1.1.2 / 1.1.3 | Low |
| | Password history | ≥ 24 | 1.1.1 | Low |
| | Lockout threshold / duration / window | ≤ 5 / ≥ 15 / ≥ 15 | 1.2.x | Low |
| **BuiltinAccounts** | Guest account | Disabled | — | Low |
| | Blank-password use | Console only | 2.3.1.x | Low |
| **Defender** | Real-time / PUA / cloud (MAPS) / sample submission | On | 18.9.x | Low |
| | Attack Surface Reduction rules (15) | Block | 18.9.x | Medium |
| **AutoRun** | Autorun/Autoplay on all drives | Disabled | 18.9.8.x | Low |
| **AuditPolicy** | Logon, account mgmt, privilege use, process creation (+cmdline), policy change, removable storage | Success/Failure per CIS | 17.x | Low |
| | Security event log size | 192 MB | 17.1.x | Low |
| **PowerShell** | Script-block / module / transcription logging | On | 18.9.100.x | Low |
| **LSAProtection** | LSASS RunAsPPL | On (**reboot**) | 18.4.x | Medium |
| **InteractiveLogon** | Inactivity lock / hide last user / cached logon count | 900s / on / 4 | 2.3.7.x | Medium |
| **RDP** | If enabled: NLA required, High encryption, no saved passwords | — | 18.x | Medium |

### Level 2 / opt-in (default OFF)

| Family | Setting | Switch | Why off by default |
|---|---|---|---|
| **CredentialGuard** | VBS + Credential Guard | `-EnableCredentialGuard` | Needs compatible hardware; can affect drivers and third-party virtualization. **Reboot.** |
| **WSH** | Disable Windows Script Host | `-Level 2` | Breaks legitimate `.vbs`/`.js` admin scripts. |
| **BitLocker** | Encrypt OS volume (XTS-AES-256) | `-EnableBitLocker` | A scripted enable **without storing the recovery key is a lockout risk**. See below. |
| **RDP (disable)** | Fully disable Remote Desktop | `-DisableRDP` | On a remote host this locks you out. |

### Attack Surface Reduction rules applied

All set to **Block**: Office child processes / executable content / process
injection / Win32-API-from-macros / communication-app children; script-based
downloaded-payload execution; obfuscated scripts; executable content from
email; untrusted/USB executables; prevalence-based executable blocking;
advanced ransomware protection; **LSASS credential theft**; PsExec/WMI-spawned
processes; Adobe Reader child processes; WMI-event-subscription persistence.

---

## BitLocker — read before using `-EnableBitLocker`

The script enables BitLocker with a **recovery-password protector**, prints the
recovery key, and writes it to `BitLocker-RecoveryKey.txt` inside the backup
bundle. **Move that key off the machine before rebooting.** If the machine
later demands the recovery key (firmware change, TPM reset) and you do not have
it, the data is unrecoverable. In a managed environment, escrow keys to AD /
Entra / Intune instead of relying on the text file.

---

## Rollback

```powershell
.\Invoke-SysReconHardening.ps1 -Rollback 'C:\ProgramData\SysRecon\hardening-backups\<stamp>'
```

Rollback restores from the bundle:

- **Registry** — re-imports the `.reg` exports of every touched key.
- **Local security policy** — re-applies `secpol-before.inf` via `secedit`.
- **Audit policy** — `auditpol /restore`.
- **Firewall** — `netsh advfirewall import`.

The **System Restore point** created at hardening time is the backstop for
anything the bundle does not cover.

**Rollback does not automatically reverse** (by design — these need a decision):

- **SMBv1 feature removal** — re-add with
  `Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.
- **BitLocker** — decrypt with `Disable-BitLocker -MountPoint C:`.
- **Credential Guard** — remove via the DeviceGuard registry keys / readiness
  tool, then reboot.

---

## Known limitations

- **Not tested end-to-end by the author on Windows.** The script parses cleanly,
  passes PSScriptAnalyzer, and its parsing / decision / selection logic is unit-
  tested, but it has **not** been run against a live Windows host by us. Validate
  on a VM (fresh + used snapshots) before production use — see the checklist
  below. This is stated for the same reason the installer's uninstall path is
  flagged as VM-pending in the changelog: we do not claim verification we did
  not perform.
- **Reboot required** for LSA protection, SMBv1 feature removal, and Credential
  Guard to take effect.
- **Home editions** lack the local security-policy engine; account-policy and
  some options are skipped (logged as `Skipped`), not failed.
- **Domain-joined hosts**: domain GPO takes precedence over local policy and may
  re-apply original values at the next policy refresh. Deploy via GPO/Intune for
  managed fleets; use this script for standalone hosts and validation.
- **Tamper Protection** cannot be toggled by script (requires Intune/MDE) and is
  not attempted.
- **Server roles**: the baseline targets workstations. The script warns when run
  on a Server/DC; review each family before applying to a server.

---

## Validation checklist (Windows VM)

1. Two snapshots: a **fresh** install and an **already-used** install.
2. `.\Invoke-SysReconHardening.ps1` (preview) — review the full change set;
   confirm nothing was applied.
3. `.\Invoke-SysReconHardening.ps1 -Apply` → **reboot** → confirm the machine
   boots and you can log in (the real fresh-vs-used safety test).
4. Run `sysrecon.exe` full scan → confirm previously-High findings (firewall
   off, SMBv1, guest enabled, weak password policy) are gone.
5. `-Rollback <bundle>` → confirm settings restored and the machine still usable.
6. Re-run `-Apply` on the hardened host → expect **zero** changes (idempotency).
