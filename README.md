<div align="center">

```
     ____                  _    ____            
    |_  /__ ___ _____ ___ | |_ / __/__ ___     
     / // _` \ V / -_)  _||  _\__ \/ -_) _|    
    /___\__,_|\_/\___\__| |_| |___/\___\__|    
```

**Windows Security Hardening Baseline**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-0078d4?style=flat-square&logo=powershell)](https://docs.microsoft.com/powershell)
[![Windows](https://img.shields.io/badge/Windows-10%2F11%20%7C%20Server%202016--2022-0078d4?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![CIS](https://img.shields.io/badge/Standard-CIS%20%7C%20DISA%20STIG%20%7C%20MS%20Baseline-00b4d8?style=flat-square)](https://cisecurity.org)
[![License](https://img.shields.io/badge/License-MIT-30d158?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-ff6b00?style=flat-square)](#)

*One script. 60+ checks. Three modes. Zero bloat.*

</div>

---

## `>_ the problem`

Most Windows environments ship with settings that are actively dangerous:
LLMNR broadcasting credentials to anyone who asks, WDigest storing plaintext
passwords in memory, SMBv1 waiting for EternalBlue, audit logs sized at 20 MB
that fill in hours. These are not edge cases — they are defaults.

`ZavetSecHardeningBaseline` fixes this. It audits your current state, applies
a hardened baseline aligned to **CIS Benchmark**, **DISA STIG**, and
**Microsoft Security Baseline**, and generates an HTML report you can hand to
a customer or attach to a ticket. If something breaks, rollback from the JSON
backup created before every change.

---

## `>_ how it works`

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
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

**Idempotent** — run Apply twice, result is identical.
**Non-destructive** — backup created before every change, full rollback available.
**Locale-independent** — audit policy uses GUIDs, not subcategory names. Works on
any Windows language.
**PsExec-compatible** — `-NonInteractive` suppresses all prompts for remote deployment.

---

## `>_ what attacks does this stop`

| Threat | MITRE | Controls |
|---|---|---|
| Responder / MITM | T1557.001 | LLMNR, NBT-NS, mDNS, WPAD disabled · SMB signing required |
| Mimikatz / LSASS dump | T1003.001 | WDigest off · LSA PPL on · Credential Guard enabled |
| Pass-the-Hash | T1550.002 | NTLMv2 only · LM hash storage off · 128-bit session |
| EternalBlue / WannaCry | T1210 | SMBv1 disabled — server and client driver |
| Lateral movement | T1021 | Remote Registry off · anonymous enumeration restricted |
| Pre-auth RDP exploits | T1021.001 | NLA enforced · encryption level high |
| USB payload delivery | T1091 | AutoRun / AutoPlay disabled on all drive types |
| PowerShell abuse | T1059.001 | Script Block + Module logging · PSv2 disabled |
| Logging blind spot | — | Security log 1 GB · 27 audit subcategories configured |

---

## `>_ coverage`

### 🌐 Network surface reduction
LLMNR, mDNS, WPAD, NBT-NS, LMHOSTS disabled. SMBv1 off on server and client
driver. SMB signing required on both sides. Anonymous SAM/share enumeration
blocked. Remote Registry disabled. `NET-001 — NET-010`

### 🔑 Credential protection
WDigest plaintext caching off. LSA Protected Process Light enabled. Credential
Guard (VBS) enabled. NTLMv2 only — LM and NTLMv1 refused. LM hash storage
disabled. 128-bit NTLM session security enforced. `CRED-001 — CRED-006`

### 🐚 PowerShell hardening
Script Block Logging (4104) and Module Logging (4103) enabled. Transcription
to `C:\ProgramData\PSTranscripts`. PSv2 engine disabled — closes the
`powershell -version 2` AMSI bypass. Execution Policy set at machine scope.
`PS-001 — PS-005`

### 📋 Audit policy
27 subcategories via `auditpol` with GUID references. Covers Logon/Logoff,
Kerberos (TGT + TGS), Process Creation, Account Management, Object Access,
Privilege Use, Policy Change, DPAPI, Scheduled Tasks, Removable Storage,
Firewall events. `AUD-001 — AUD-027`

### 🖥️ System hardening
UAC full enforcement with secure desktop. AutoRun/AutoPlay disabled. Firewall
on all profiles. RDP NLA required. DEP AlwaysOn. Security log 1 GB / overwrite.
DoH policy. RDP encryption high. Print Spooler disable opt-in (PrintNightmare).
`SYS-001 — SYS-010`

---

## `>_ safe to run — read this first`

> ⚠️ **Test in a non-production environment before deploying at scale.**

**What may break:**

- **SMBv1 disable** — legacy devices that only speak SMBv1 (old printers, NAS,
  XP/2003) lose network access. Run `Get-SmbConnection` first to identify
  dependent devices.
- **SMB signing required** — clients without signing support are rejected.
  Negligible in modern environments, check in legacy/mixed estates.
- **Credential Guard** — requires UEFI + Secure Boot + VBS hardware.
  Skipped gracefully on incompatible machines.
- **NTLMv2 only** — systems that only support LM/NTLMv1 fail authentication.
  Rare in IT, more common in OT/industrial environments.
- **Print Spooler** (`-EnablePrintSpoolerDisable`) — printing stops entirely.
  Apply only to non-printing machines.
- **PSv2 disable** — requires reboot. Automation calling `powershell -version 2`
  will break.

**Reboot required for:** Credential Guard · DEP AlwaysOn · PSv2 disable · SMBv1 client driver.

**Apply runtime:** ~20–60 seconds on a modern workstation. Audit mode is faster.
Audit policy configuration (27 subcategories via `auditpol`) accounts for most
of the runtime on domain-joined machines.

---

## `>_ quickstart`

### Option A — BAT launcher (recommended for manual use)

Right-click `Run-Hardening.bat` → **Run as administrator.**

```
  ============================================================
   ZavetSec - Windows Security Hardening Baseline
  ============================================================

   [1]  AUDIT    - Check current state (no changes)
   [2]  APPLY    - Apply all hardening settings
   [3]  ROLLBACK - Revert changes (requires backup file)
   [4]  EXIT
```

Creates `Reports\` automatically. ROLLBACK lists backups by number — no path
entry required.

### Option B — PowerShell directly

```powershell
# Audit — zero changes
.\ZavetSecHardeningBaseline.ps1 -Mode Audit

# Apply (interactive)
.\ZavetSecHardeningBaseline.ps1 -Mode Apply

# Apply — no prompts (PsExec / automation)
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive

# Rollback
.\ZavetSecHardeningBaseline.ps1 -Mode Rollback `
    -BackupPath .\Reports\HardeningBackup_20260318_120000.json

# Skip sections
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipAuditPolicy
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipNetworkHardening
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipCredentialProtection
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipPowerShell

# PrintNightmare mitigation (opt-in)
.\ZavetSecHardeningBaseline.ps1 -Mode Apply -EnablePrintSpoolerDisable
```

### Option C — Mass deployment via PsExec

```powershell
psexec \\TARGET -s -c .\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive
```

---

## `>_ deployment timeline`

```
Day 0    Audit on a representative sample.
         Review the report. Identify legacy dependencies
         (SMBv1 devices, NTLMv1 systems, old automation).

Day 1–7  Fix dependencies. Test Apply in a lab VM.
         Confirm rollback works from the generated backup.

Day 7    Apply to a pilot group (5–10 machines).
         Monitor for 48 hours. Check helpdesk tickets.

Day 14+  Roll out in batches. Reboot machines that require it.

Day 30   Re-run Audit across all machines.
         Compare compliance % before and after.
         Attach report to change management record.
```

---

## `>_ vs alternatives`

| Tool | Rollback | Report | Offline | PS 5.1 |
|---|---|---|---|---|
| **ZavetSecHardeningBaseline** | ✅ JSON backup | ✅ HTML | ✅ | ✅ |
| CIS CAT Pro | ❌ | ✅ | ❌ requires Java | ❌ |
| LGPO.exe | manual | ❌ | ✅ | N/A |
| Microsoft SCT (GPO) | via GPO restore | ❌ | ✅ | partial |

---

## `>_ tested environments`

| OS | Domain | Workgroup |
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
| `-Mode Audit\|Apply\|Rollback` | `Audit` | Operation mode |
| `-BackupPath` | script dir | JSON backup path |
| `-OutputPath` | script dir | HTML report path |
| `-SkipAuditPolicy` | — | Skip audit policy section |
| `-SkipNetworkHardening` | — | Skip network section |
| `-SkipPowerShell` | — | Skip PowerShell section |
| `-SkipCredentialProtection` | — | Skip credentials section |
| `-EnablePrintSpoolerDisable` | — | Disable Print Spooler (opt-in) |
| `-NonInteractive` | — | Suppress all prompts |

---

## `>_ disclaimer`

> This script modifies security-relevant system settings. Always run Audit
> mode first. Always test Apply in a non-production environment before
> deploying at scale. The author assumes no responsibility for system
> instability, application breakage, or data loss resulting from use of
> this tool.

---

<div align="center">

**ZavetSec** — security tooling for those who read logs at 2am

[GitHub](https://github.com/zavetsec) · MIT License

</div>
