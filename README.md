# ZavetSec-Harden

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-0078d4?style=flat-square&logo=powershell)](https://docs.microsoft.com/powershell)
[![Windows](https://img.shields.io/badge/Windows-10%2F11%20%7C%20Server%202016--2022-0078d4?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![CIS](https://img.shields.io/badge/Standard-CIS%20%7C%20DISA%20STIG%20%7C%20MS%20Baseline-00b4d8?style=flat-square)](https://cisecurity.org)
[![License](https://img.shields.io/badge/License-MIT-30d158?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.2-ff6b00?style=flat-square)](#)

**Windows ships with insecure defaults. This fixes them.**

**One script. 60 checks. Four modes. Zero bloat.**

### ⚡ Why use this

✔ No install  
✔ No internet required  
✔ Works on any Windows 10/11/Server  
✔ Safe to rollback  
✔ Used in real-world environments: standalone hosts, lab fleets, and incident response

---

> **Find and fix 60+ insecure Windows defaults that enable credential theft and lateral movement.**
> Zero dependencies &nbsp;·&nbsp; No AD &nbsp;·&nbsp; Safe rollback &nbsp;·&nbsp; Self-contained HTML report
>
> Settings derived from CIS Benchmark, DISA STIG, and Microsoft Security Baseline — **mapped and adapted** for standalone and offline environments.

---

## `>_ the problem`

Most Windows environments ship with settings that are actively dangerous:
LLMNR broadcasting credentials to anyone who asks, WDigest storing plaintext
passwords in memory, SMBv1 waiting for EternalBlue, audit logs sized at 20 MB
that fill in hours. These are not misconfigurations — **they are shipped this way, on every fresh install.**

`ZavetSec-Harden` fixes this. It audits your current state, applies
a hardened baseline aligned to **CIS Benchmark**, **DISA STIG**, and
**Microsoft Security Baseline**, and generates an HTML report you can hand to
a customer or attach to a ticket. If something breaks, rollback from the JSON
backup created before every change.

---

## `>_ who this is for`

- **SOC analysts** running rapid host assessments
- **DFIR / IR teams** hardening a foothold post-incident
- **Sysadmins** without AD / GPO control (workgroup, cloud-joined, standalone)
- **Red teamers** validating baseline weaknesses before an engagement
- **Anyone** who needs to prove a machine meets a compliance baseline

---

## `>_ 10-second start`

```powershell
.\ZavetSec-Harden.ps1
```
```
  [1]  Audit     - Check current state, no changes made
  [2]  Apply     - Harden the system (backup created first)
  [3]  Rollback  - Revert to pre-hardening state from backup
  [4]  Defaults  - Reset all settings to Windows out-of-box defaults
```

Choose `[1] Audit` → open the HTML report → review what's exposed → come back and hit `[2] Apply`.

---

## `>_ how it works`

```
Audit    → detect insecure defaults (no changes)
Apply    → backup → harden → verify
Rollback → restore exact previous state
```

```
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │   Audit mode        Read current state                  │
  │       │                    │                            │
  │       ▼                    ▼                            │
  │   State detection   HTML report generated               │
  │       │                                                 │
  │   Apply mode        JSON backup → apply changes         │
  │       │                    │                            │
  │       ▼                    ▼                            │
  │   Change engine     Verify each setting post-apply      │
  │       │                                                 │
  │   Rollback mode     Read backup → restore prior state   │
  │       │                                                 │
  │   Defaults mode     Reset to Windows out-of-box state   │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

**Idempotent** — run Apply twice, result is identical.  
**Non-destructive** — JSON backup before every change, full rollback available.  
**Locale-independent** — audit policy uses GUIDs, works on any Windows language.  
**PsExec-compatible** — `-NonInteractive` flag for remote/automated deployment.

---

## `>_ what attacks does this stop`

| Threat | Impact | MITRE | Controls |
|---|---|---|---|
| 🔴 Responder / MITM | Credential capture over LAN | T1557.001 | LLMNR, NBT-NS, mDNS, WPAD disabled · SMB signing required |
| 🔴 Mimikatz / LSASS dump | Plaintext passwords from memory | T1003.001 | WDigest off · LSA PPL on · Credential Guard enabled |
| 🔴 Pass-the-Hash | Lateral movement without password | T1550.002 | NTLMv2 only · LM hash storage off · 128-bit session |
| 🔴 EternalBlue / WannaCry | Remote code execution, ransomware | T1210 | SMBv1 disabled — server and client driver |
| 🟠 Lateral movement | Spread across the network | T1021 | Remote Registry off · anonymous enumeration restricted |
| 🟠 Pre-auth RDP exploits | RCE before login prompt | T1021.001 | NLA enforced · encryption level high |
| 🟠 USB payload delivery | Autorun from physical media | T1091 | AutoRun / AutoPlay disabled on all drive types |
| 🟠 PowerShell abuse | LOLBin / fileless execution | T1059.001 | Script Block + Module logging · PSv2 disabled |
| 🟡 Logging blind spot | Undetected attacker activity | — | Security log 1 GB · 29 audit subcategory checks |

---

## `>_ coverage`

### 🌐 Network surface reduction
- LLMNR — **disabled** (Responder bait)
- mDNS — **disabled**
- WPAD — **disabled** (proxy hijack vector)
- NBT-NS — **disabled** on all adapters
- LMHOSTS lookup — **disabled**
- SMBv1 server — **disabled**
- SMBv1 client driver (mrxsmb10) — **disabled** (reboot required)
- SMB signing server — **required**
- SMB signing client — **required**
- Anonymous SAM/share enumeration — **blocked**
- Remote Registry service — **disabled**

`NET-001 — NET-010`

### 🔑 Credential protection
- WDigest plaintext caching — **disabled**
- LSA Protected Process Light — **enabled**
- Credential Guard (VBS) — **enabled**
- LAN Manager auth level — **NTLMv2 only** (LM/NTLMv1 refused)
- LM hash storage — **disabled**
- NTLM 128-bit session security — **enforced**

`CRED-001 — CRED-006`

### 🐚 PowerShell hardening
- Script Block Logging (4104) — **enabled**
- Module Logging (4103) — **enabled**
- Transcription to `C:\ProgramData\PSTranscripts` — **enabled**
- PowerShell v2 engine — **disabled** (AMSI bypass vector)
- Execution Policy (RemoteSigned) — **set at machine scope**

`PS-001 — PS-005`

### 📋 Audit policy
27 subcategories via `auditpol` with GUID references — locale-independent, works
on any Windows language. Plus command-line capture in 4688, and
`SCENoApplyLegacyAuditPolicy` to prevent GPO from silently overriding subcategory
settings. Covers Logon/Logoff, Kerberos (TGT + TGS), Process Creation, Account
Management, Object Access, Privilege Use, Policy Change, DPAPI, Scheduled Tasks,
Removable Storage, Firewall events.

`AUD-001 — AUD-029`

### 🖥️ System hardening
- UAC — **full enforcement** with secure desktop prompt
- AutoRun / AutoPlay — **disabled** on all drive types
- Windows Firewall — **enabled** on all profiles (Domain, Private, Public)
- RDP NLA — **required**
- DEP — **AlwaysOn** (reboot required)
- Security log — **1 GB / overwrite**
- System + Application logs — **256 MB / overwrite**
- DNS-over-HTTPS policy — **enabled**
- RDP encryption — **High** (MinEncryptionLevel=3)
- Print Spooler disable — **opt-in** (PrintNightmare mitigation)

`SYS-001 — SYS-010`

---

## `>_ output — HTML report`

Every run produces a self-contained, dark-themed HTML report — no external
dependencies, opens in any browser:

- **Compliance score gauge** (0–100%) — green ≥80%, orange 60–79%, red <60%
- **Per-category breakdown** with pass/fail bars
- **Device Profile Applied** section — which sections ran, which were skipped and why
- **Full check list** — ID · severity · MITRE technique · result · apply status · remediation command
- **Live filter** — FAIL only · CRITICAL · HIGH · by category · free text search
- **Rollback command** pre-filled at the bottom with the backup path

Hand it to a customer. Attach it to a change management record. Run before/after to show delta.

> 📸 **Screenshot:**

<img width="1443" height="771" alt="image" src="https://github.com/user-attachments/assets/53a22b0a-7446-4d6c-a336-4272f34bb403" />

---

## `>_ why this, not that`

| | ZavetSec-Harden | CIS CAT Pro | LGPO.exe | MS Security Baseline (GPO) |
|---|---|---|---|---|
| **Rollback** | ✅ JSON backup | ❌ | manual GPO restore | partial |
| **HTML report** | ✅ per-check, MITRE | ✅ | ❌ | ❌ |
| **No dependencies** | ✅ PS 5.1 only | ❌ Java required | ✅ | ❌ AD/DC required |
| **Offline** | ✅ | ❌ | ✅ | ✅ |
| **Audit-only mode** | ✅ | ✅ | ❌ | ❌ |
| **Device profiles** | ✅ per-role safe presets | ❌ | ❌ | ❌ |
| **Selective apply** | ✅ profiles + skip flags | ❌ | ❌ | ❌ |
| **PsExec / automation** | ✅ `-NonInteractive` | ❌ | partial | partial |

The main difference: most alternatives either change the system with no easy undo,
require infrastructure, or produce no actionable report.
This tool is built to be **reversible, reportable, and runnable anywhere.**
Designed for standalone and offline environments — no infrastructure required.

> *Feature comparison based on default/standalone usage scenarios.*

---

## `>_ quickstart`

### Option A — interactive (recommended)

```powershell
.\ZavetSec-Harden.ps1
```

The script walks you through mode selection, then device profile selection for Apply,
then backup file selection for Rollback. Every menu has **[0] Back**. Invalid input
loops — nothing exits unexpectedly.

**Apply flow after selecting [2]:**

```
  ==============================================================
    Select device profile:
  ==============================================================

    [1]  Workstation       - endpoint, full hardening applied
    [2]  File Server       - SMBv1/signing critical, skip Credential Guard
    [3]  Domain Controller - skip Credential Guard + audit policy (use GPO)
    [4]  RDS               - terminal server, full hardening + transcription note
    [5]  SQL / DB Server   - skip Credential Guard, check Remote Registry
    [6]  Exchange / Mail   - skip network + credential sections (NTLM/SMB deps)
    [7]  Print Server      - Print Spooler preserved, skip Credential Guard

    [8]  ALL               - apply all 60 checks, operator takes full responsibility

    [0]  Back              - return to mode selection
```

**Rollback flow after selecting [3]:**

```
    [ 1]  HardeningBackup_20260422_143012.json  [2026-04-22 14:30:12]  8.4 KB
    [ 2]  HardeningBackup_20260418_091544.json  [2026-04-18 09:15:44]  7.1 KB

    [0]   Back
```

### Option B — direct flags

```powershell
# Audit -- zero changes
.\ZavetSec-Harden.ps1 -Mode Audit

# Apply with device profile (no interactive menus)
.\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile Workstation
.\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile DomainController
.\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile All

# Apply -- fully automated, no prompts
.\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile Workstation -NonInteractive

# Rollback -- interactive backup selection
.\ZavetSec-Harden.ps1 -Mode Rollback

# Rollback -- explicit backup path (automation)
.\ZavetSec-Harden.ps1 -Mode Rollback -BackupPath .\HardeningBackup_20260422_143012.json

# Reset to Windows defaults (when backup is unavailable)
.\ZavetSec-Harden.ps1 -Mode Defaults

# Skip individual sections manually (Custom profile)
.\ZavetSec-Harden.ps1 -Mode Apply -SkipAuditPolicy
.\ZavetSec-Harden.ps1 -Mode Apply -SkipNetworkHardening
.\ZavetSec-Harden.ps1 -Mode Apply -SkipCredentialProtection
.\ZavetSec-Harden.ps1 -Mode Apply -SkipPowerShell

# PrintNightmare mitigation (opt-in)
.\ZavetSec-Harden.ps1 -Mode Apply -EnablePrintSpoolerDisable
```

### Option C — mass deployment via PsExec

```powershell
psexec \\TARGET -s -c .\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile Workstation -NonInteractive
```

---

## `>_ device profiles`

Profiles automatically configure `Skip*` flags for a given role. The HTML report
includes a **Device Profile Applied** section (02.5) with the full applied/skipped
list and the reason for each skip.

| Profile | Skip Network | Skip Credentials | Skip Audit Policy | Print Spooler |
|---|---|---|---|---|
| `Workstation` | — | — | — | opt-in |
| `FileServer` | — | ✓ | — | opt-in |
| `DomainController` | — | ✓ | ✓ (manage via GPO) | opt-in |
| `RDS` | — | — | — | opt-in |
| `SQL` | — | ✓ | — | opt-in |
| `Exchange` | ✓ | ✓ | — | opt-in |
| `PrintServer` | — | ✓ | — | **never** |
| `All` | — | — | — | **always on** |
| `Custom` | manual `-Skip*` flags | | | |

**Why credentials are skipped on most server profiles:** Credential Guard requires
UEFI + Secure Boot + VBS and is explicitly unsupported on Domain Controllers per
Microsoft documentation. On SQL Server and some storage configurations it can cause
instability. `CRED-001` (WDigest) and `CRED-002` (LSA PPL) are still applied — only
`CRED-003` (Credential Guard) is the problematic one, but the section is skipped as
a whole to avoid partial application.

> ⚠️ Always run Audit first on servers before selecting a profile and applying.

---

## `>_ safe to run — read this first`

> ⚠️ **Always run Audit first. Test Apply in a non-production VM before deploying at scale.**

**What may break:**

- **SMBv1 disable** — legacy devices that only speak SMBv1 (old printers, NAS, XP/2003) lose network access. Run `Get-SmbConnection` first to identify them.
- **SMB signing required** — clients without signing support are rejected. Negligible in modern environments, check in legacy/mixed estates.
- **Credential Guard** — requires UEFI + Secure Boot + VBS hardware. Skipped gracefully on incompatible machines.
- **NTLMv2 only** — systems that only support LM/NTLMv1 fail authentication. Rare in IT, more common in OT/industrial environments.
- **Print Spooler** (`-EnablePrintSpoolerDisable`) — printing stops entirely. Apply only to non-printing machines.
- **PSv2 disable** — requires reboot. Automation calling `powershell -version 2` will break.

**Reboot required for:** Credential Guard · DEP AlwaysOn · PSv2 disable · SMBv1 client driver.

**Runtime:** Audit ~10–30 seconds. Apply ~20–60 seconds — most of that is the 27 `auditpol` subcategory calls. Tested via PsExec fan-out on lab fleet without issues.

---

## `>_ deployment timeline`

```
Day 0     Audit on a representative sample.
          Review the HTML report. Identify legacy dependencies
          (SMBv1 devices, NTLMv1 systems, old automation scripts).

Day 1-7   Fix dependencies. Test Apply in a lab VM.
          Confirm rollback works from the generated backup.

Day 7     Apply to a pilot group (5-10 machines).
          Monitor for 48 hours. Check application behaviour and helpdesk.

Day 14+   Roll out in batches. Reboot machines that require it.

Day 30    Re-run Audit across all machines.
          Compare compliance % before and after.
          Attach the HTML report to the change management record.
```

---

## `>_ emergency reset`

Two recovery paths are available — from the interactive menu `[4] Defaults` or directly:

```powershell
# Path 1 -- precise restore from backup (preferred)
.\ZavetSec-Harden.ps1 -Mode Rollback
# Interactive list of available backups shown automatically

# Path 2 -- full reset to Windows out-of-box defaults (when backup unavailable)
.\ZavetSec-Harden.ps1 -Mode Defaults
# or directly:
.\WindowsDefaults.ps1 -NonInteractive
```

**Decision tree:**

```
Something broke after Apply
        |
        +-- JSON backup exists?
        |       YES -> .\ZavetSec-Harden.ps1 -Mode Rollback
        |                    (precise restore of your exact prior values)
        |
        +-- No backup / hardened by another tool?
                YES -> .\ZavetSec-Harden.ps1 -Mode Defaults
                             (full reset to clean Windows out-of-box state)
```

---

## `>_ tested environments`

| OS | Domain-joined | Workgroup |
|---|---|---|
| Windows 10 21H2+ | ✅ | ✅ |
| Windows 11 22H2+ | ✅ | ✅ |
| Windows Server 2016 | ✅ | ✅ |
| Windows Server 2019 | ✅ | ✅ |
| Windows Server 2022 | ✅ | ✅ |
| Server Core | ✅ | ✅ |

---

## `>_ parameters`

| Parameter | Default | Description |
|---|---|---|
| `-Mode Audit\|Apply\|Rollback\|Defaults` | interactive menu | Operation mode. Omit to get the interactive mode selection menu. |
| `-DeviceProfile` | `Custom` | Safe preset for device role. See Device Profiles table. Interactive menu shown on Apply if omitted. |
| `-BackupPath` | `<ScriptDir>` | JSON backup path. In Rollback mode, an interactive list is shown if omitted. |
| `-OutputPath` | `<ScriptDir>` | HTML report output path. |
| `-SkipAuditPolicy` | — | Skip audit policy section. Overridden by profile selection. |
| `-SkipNetworkHardening` | — | Skip network section. Overridden by profile selection. |
| `-SkipPowerShell` | — | Skip PowerShell section. Overridden by profile selection. |
| `-SkipCredentialProtection` | — | Skip credentials section. Overridden by profile selection. |
| `-EnablePrintSpoolerDisable` | — | Disable Print Spooler (opt-in). Ignored on `PrintServer` profile. |
| `-NonInteractive` | — | Suppress all prompts. Requires explicit `-Mode` and `-DeviceProfile` when used with Apply. |

---

## `>_ antivirus exclusions`

Some EDR/AV solutions may flag the script due to its behaviour — registry changes,
service control, `auditpol.exe` calls, and `.ps1` execution.
This is expected and does not indicate malicious intent.

If your AV triggers on it, review the source code (fully open-source)
and consider adding an exclusion for:

```
ZavetSec-Harden.ps1
```

---

## `>_ part of the ZavetSec DFIR toolkit`

`ZavetSec-Harden` is one module in the **ZavetSec** open-source SOC/DFIR
toolkit — a collection of standalone PowerShell tools built for practitioners who
work in real environments: mixed OS fleets, no internet, constrained budgets, and
incidents that don't wait.

Every tool in the toolkit follows the same design contract:

- **PS 5.1 only** — runs on anything from Server 2016 to Windows 11, no prerequisites
- **Zero dependencies** — single script file, no modules to install, no internet required
- **Self-contained HTML reports** — dark-themed, filterable, ready to attach to a ticket
- **MITRE ATT&CK mapped** — findings tied to techniques, not just abstract recommendations
- **PsExec / automation compatible** — `-NonInteractive` flag across all tools
- **Reversible** — where changes are made, a rollback path always exists

The toolkit covers the full incident response lifecycle: live triage and artifact
collection, threat intel enrichment, network discovery and vulnerability surface
mapping, lateral movement detection, credential exposure analysis, and hardening
with compliance reporting. Tools are designed to be chained as a pipeline or
used independently depending on what the engagement calls for.

**→ [github.com/zavetsec](https://github.com/zavetsec)**

---

## `>_ if this helped`

If this saved you time during an audit or incident — consider starring the repo.
It helps other defenders find the tool.

---

## `>_ disclaimer`

> This script modifies security-relevant system settings. Always run Audit
> mode first. Always test Apply in a non-production environment before
> deploying at scale. The author assumes no responsibility for system
> instability, application breakage, or data loss resulting from use of
> this tool.

---

<div align="center">

**[ZavetSec](https://github.com/zavetsec)** — security tooling for those who read logs at 2 AM

*⭐ Star the repo to help other defenders find it.*

</div>
