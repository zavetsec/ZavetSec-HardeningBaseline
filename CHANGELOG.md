# Changelog

All notable changes to ZavetSecHardeningBaseline will be documented here.

---

## [1.0] — 2026-03-18

### Initial release

**Script**
- Audit / Apply / Rollback modes with JSON backup and HTML report
- 60+ checks across 5 categories: Network, Credentials, PowerShell, Audit Policy, System
- `-NonInteractive` flag for PsExec and automated deployment
- Selective apply via `-SkipAuditPolicy`, `-SkipNetworkHardening`, `-SkipCredentialProtection`, `-SkipPowerShell`
- Optional Print Spooler disable via `-EnablePrintSpoolerDisable`
- Audit policy configured via auditpol GUIDs — locale-independent
- Dark-themed HTML report with compliance gauge, MITRE references, filterable check table

**Checks added**
- NET-001 — NET-010: LLMNR, mDNS, WPAD, SMBv1, SMB Signing, NBT-NS, LMHOSTS, Anon Enum, Remote Registry
- CRED-001 — CRED-006: WDigest, LSA PPL, Credential Guard, NTLMv2, LM Hash, 128-bit Session
- PS-001 — PS-005: Script Block Logging, Module Logging, Transcription, PSv2 Disable, Exec Policy
- AUD-001 — AUD-027: 27 audit subcategories via auditpol
- SYS-001 — SYS-010: UAC, AutoRun, Firewall, RDP NLA, DEP, Event Log sizing, DoH, RDP Encryption, Print Spooler (opt-in)

**Launcher**
- `Run-Hardening.bat` — interactive menu launcher with Reports\ folder management and numbered backup selection for Rollback

---

## Roadmap

- [ ] v1.1 — HTML report screenshot in README
- [ ] v1.1 — CHANGELOG embedded in HTML report footer
- [ ] v1.2 — WMI/DCOM hardening checks
- [ ] v1.2 — Windows Defender baseline checks (tamper protection, cloud delivery)
- [ ] v1.3 — CSV export for SIEM/ticketing integration
- [ ] v1.3 — Verbose logging mode (`-Verbose` output to file)
