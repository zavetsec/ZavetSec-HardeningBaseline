#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSec-Harden - Windows security hardening baseline by ZavetSec.
.DESCRIPTION
    Applies and audits Windows security hardening settings:

    NETWORK PROTOCOLS:
      - Disable LLMNR (Link-Local Multicast Name Resolution)
      - Disable NBT-NS (NetBIOS over TCP/IP Name Service)
      - Disable mDNS (Multicast DNS)
      - Disable WPAD (Web Proxy Auto-Discovery)
      - Disable SMBv1 (Server Message Block v1)
      - Enable SMB signing (client + server, required)
      - Disable NetBIOS over TCP on all adapters
      - Disable LMHOSTS lookup

    AUDIT POLICY:
      - Process Creation / Termination (4688/4689)
      - Logon / Logoff (4624/4625/4634/4647)
      - Account Logon (4768/4769/4771/4776)
      - Account Management (4720/4722/4724/4725/4726/4732/4733/4740)
      - Object Access (4663 - file/registry audit)
      - Privilege Use (4672/4673)
      - Policy Change (4719/4907)
      - System events (4608/4609/4616/4657)
      - DS Access (4662 - AD object access)
      - Detailed Tracking - DPAPI, RPC

    ADDITIONAL HARDENING:
      - Enable PowerShell Script Block Logging (4104)
      - Enable PowerShell Module Logging
      - Enable PowerShell Transcription
      - Disable PowerShell v2 (downgrade attack vector)
      - Enable Windows Defender Credential Guard (if supported)
      - Enable LSA Protection (RunAsPPL)
      - Disable WDigest plaintext credential caching
      - Disable AutoRun / AutoPlay
      - Enable Windows Firewall (all profiles)
      - Restrict anonymous enumeration (RestrictAnonymous)
      - Disable Remote Registry
      - Disable DCOM (optional)
      - Enable UAC (full enforcement)
      - Restrict RDP NLA (Network Level Authentication)
      - Disable Print Spooler on non-print servers (optional)
      - Enable Windows Event Log service
      - Increase Event Log sizes
      - Enable DEP (Data Execution Prevention)
      - Disable unused services (LLMNR/WPAD/Xbox/etc)
      - Restrict Remote SAM enumeration (NET-011)
      - Clear null-session pipes and shares (NET-012)
      - Disable IP source routing IPv4+IPv6 (NET-013)
      - Disable ICMP redirect acceptance (NET-014)
      - Enable SEHOP exception chain validation (CRED-007)
      - Mitigate CredSSP Oracle CVE-2018-0886 (CRED-008)
      - Kerberos AES-only encryption types (CRED-009)
      - Remote Credential Guard for RDP (CRED-010)
      - Netlogon signed/sealed secure channel (CRED-011)
      - Process creation command line audit Event 4688 (SYS-011)
      - Protect auditpol subcategories from GPO override (SYS-012)
      - Authenticode padding check Flame mitigation (SYS-013)
      - NTLM incoming traffic audit Event 8004 (SYS-014)
      - Disable NULL session fallback for LocalSystem (SYS-015)
      - Self-unblock Zone.Identifier on startup (prevents PS-005 locking script)

.PARAMETER Mode
    'Audit'  - Check settings, report only, no changes (default)
    'Apply'  - Apply all hardening settings
    'Rollback' - Revert changes made by a previous Apply (reads backup)
.PARAMETER BackupPath
    Path for settings backup JSON (used by Apply and Rollback).
    Default = <ScriptDir>\HardeningBackup_<timestamp>.json  (same folder as the script)
.PARAMETER DeviceProfile
    Safe apply preset for a specific device role. Sets Skip* flags automatically.
    Workstation       - Apply everything (safest, recommended for endpoints)
    FileServer        - Skip CredentialProtection (Credential Guard)
    DomainController  - Skip CredentialProtection + AuditPolicy (manage audit via GPO)
    RDS               - Apply everything (note PS transcription volume on busy servers)
    SQL               - Skip CredentialProtection
    Exchange          - Skip Network + CredentialProtection (Exchange NTLM/SMB deps)
    PrintServer       - Skip CredentialProtection; Print Spooler never disabled
    All               - Apply ALL 60 checks incl. Credential Guard + Spooler disable
    Custom            - Use manual -Skip* flags (default, legacy behaviour)
.PARAMETER OutputPath
    HTML report path. Default = ScriptDir\ZavetSecHardening_<timestamp>.html
.PARAMETER SkipAuditPolicy
    Skip audit policy configuration.
.PARAMETER SkipNetworkHardening
    Skip network protocol hardening (LLMNR/NBT-NS/SMB).
.PARAMETER SkipPowerShell
    Skip PowerShell hardening (logging, PS v2 disable).
.PARAMETER SkipCredentialProtection
    Skip LSA/WDigest/Credential Guard settings.
.PARAMETER EnablePrintSpoolerDisable
    Also disable Print Spooler service (only on non-print-servers).
.EXAMPLE
    # Audit only - see current state:
    .\ZavetSec-Harden.ps1 -Mode Audit

    # Apply all hardening:
    .\ZavetSec-Harden.ps1 -Mode Apply

    # Apply with custom backup:
    .\ZavetSec-Harden.ps1 -Mode Apply -BackupPath C:\DFIR\backup.json

    # Rollback:
    .\ZavetSec-Harden.ps1 -Mode Rollback -BackupPath C:\DFIR\backup.json

    # Apply with device profile (interactive menu if profile omitted in Apply mode):
    .\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile Workstation
    .\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile DomainController
    .\ZavetSec-Harden.ps1 -Mode Apply -DeviceProfile All
    .\ZavetSec-Harden.ps1 -Mode Apply  # shows interactive profile menu

    # Partial apply (skip audit policy):
    .\ZavetSec-Harden.ps1 -Mode Apply -SkipAuditPolicy
.NOTES
    ================================================================
    ZavetSec | https://github.com/zavetsec
    Script   : ZavetSec-Harden
    Version  : 1.4
    Author   : ZavetSec
    License  : MIT
    ================================================================
    Covers  : CIS Benchmark, DISA STIG, Microsoft Security Baseline
    Tested  : Windows 10/11, Windows Server 2016/2019/2022
    Requires: PowerShell 5.1+, Local Administrator rights
    Reboot  : Some settings require reboot (Credential Guard, DEP)
    Backup  : Always created before Apply. Use -Mode Rollback to revert
    ================================================================
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Audit','Apply','Rollback','Defaults','')]
    [string]$Mode                      = '',
    [string]$BackupPath                = '',
    [string]$OutputPath                = '',
    # Device profile -- sets safe Skip flags automatically.
    # 'Custom' = manual flags below. 'All' = apply everything.
    [ValidateSet('Workstation','FileServer','DomainController','RDS','SQL','Exchange','PrintServer','All','Custom')]
    [string]$DeviceProfile             = 'Custom',
    [switch]$SkipAuditPolicy,
    [switch]$SkipNetworkHardening,
    [switch]$SkipPowerShell,
    [switch]$SkipCredentialProtection,
    [switch]$EnablePrintSpoolerDisable,
    [switch]$NonInteractive  # Suppress all prompts (for PsExec/remote/scheduled task use)
)

# -------------------------------------------------------
# Self-unblock: remove Zone.Identifier ADS if present.
# PS-005 sets ExecutionPolicy=RemoteSigned via registry (GPO level).
# Files downloaded from the internet carry a Zone.Identifier NTFS stream
# that marks them as "untrusted remote" -- RemoteSigned then blocks them
# even though they are physically local.
# We strip the mark from this script file before any other code runs,
# so subsequent re-launches work without -ExecutionPolicy Bypass.
# This is safe: equivalent to right-click -> Properties -> Unblock in Explorer.
# -------------------------------------------------------
try {
    $selfPath = $MyInvocation.MyCommand.Path
    if ($selfPath -and (Test-Path $selfPath)) {
        $zoneStream = Get-Item -Path $selfPath -Stream 'Zone.Identifier' -EA SilentlyContinue
        if ($zoneStream) {
            Remove-Item -Path $selfPath -Stream 'Zone.Identifier' -Force -EA SilentlyContinue
            Write-Host "  [..] Zone.Identifier removed from script file (Unblock-File applied)." -ForegroundColor DarkGray
        }
    }
} catch {
    # Non-fatal -- NTFS ADS removal may fail on FAT32 / network shares; ignore silently
}

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

$global:StartTime = Get-Date
$global:Checks    = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:Backup    = [ordered]@{}
$global:Applied   = 0
$global:Skipped   = 0
$global:Failed    = 0
# is* flags initialized to $false -- resolved after interactive menu (below banner)
$isApply    = $false
$isAudit    = $false
$isRollback = $false

# Resolve default paths here (not in param block - avoids PS expression parsing issues)
$_stamp = $global:StartTime.ToString('yyyyMMdd_HHmmss')
$_desk  = Join-Path $env:USERPROFILE 'Desktop'
if (-not (Test-Path $_desk)) { $_desk = $env:TEMP }
if ([string]::IsNullOrEmpty($BackupPath)) {
    $BackupPath = Join-Path $PSScriptRoot "HardeningBackup_$_stamp.json"
}
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "ZavetSecHardening_$_stamp.html"
}

# -------------------------------------------------------
# Console helpers
# -------------------------------------------------------
function Write-Phase { param([string]$T)
    Write-Host ""
    Write-Host "  [>>] $T" -ForegroundColor Cyan
}
function Write-Pass  { param([string]$M); Write-Host "  [OK] $M" -ForegroundColor Green }
function Write-Fail  { param([string]$M); Write-Host "  [!!] $M" -ForegroundColor Yellow }
function Write-Apply { param([string]$M); Write-Host "  [>>] $M" -ForegroundColor DarkCyan }
function Write-Err   { param([string]$M); Write-Host "  [XX] $M" -ForegroundColor Red }
function Write-Info  { param([string]$M); Write-Host "  [..] $M" -ForegroundColor DarkGray }

# -------------------------------------------------------
# Check/Apply engine
# -------------------------------------------------------
function Test-And-Set {
    param(
        [string]$ID,
        [string]$Category,
        [string]$Name,
        [string]$Description,
        [string]$Severity,         # CRITICAL / HIGH / MEDIUM / LOW
        [scriptblock]$CheckScript,   # Returns $true if compliant. Throw 'SKIP:<reason>' to mark N/A.
        [scriptblock]$ApplyScript,   # Throw 'SKIP:<reason>' to mark N/A (e.g. unsupported OS, hardware).
        [scriptblock]$BackupScript,
        [string]$Reference    = '',     # CIS/MITRE reference
        [string]$Remediation  = '',     # Manual fix command
        [string]$RebootRequired = 'No'
    )

    $compliant  = $false
    $checkError = ''
    $applyStatus= ''
    $skipReason = ''

    # --- CHECK ---
    try {
        $compliant = & $CheckScript
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match '^SKIP:(.*)$') {
            # CheckScript explicitly says "this control does not apply to this host"
            $skipReason = $Matches[1].Trim()
            $applyStatus = 'NotApplicable'
            Write-Info "$Name [N/A: $skipReason]"
            $global:Skipped++
            $global:Checks.Add([PSCustomObject]@{
                ID             = $ID
                Category       = $Category
                Name           = $Name
                Description    = $Description
                Severity       = $Severity
                Compliant      = $null         # N/A -- not compliant, not non-compliant
                ApplyStatus    = $applyStatus
                CheckError     = ''
                SkipReason     = $skipReason
                Reference      = $Reference
                Remediation    = $Remediation
                RebootRequired = $RebootRequired
            })
            return
        }
        $checkError = $msg
        $compliant  = $false
    }

    if ($compliant) {
        Write-Pass "$Name"
    } else {
        Write-Fail "$Name [NOT COMPLIANT]"
    }

    # --- BACKUP (before apply) ---
    if ($isApply -and -not $compliant -and $BackupScript) {
        try {
            $bkVal = & $BackupScript
            $global:Backup[$ID] = $bkVal
        } catch {}
    }

    # --- APPLY ---
    if ($isApply -and -not $compliant) {
        $applyThrew = $false
        try {
            Write-Apply "  Applying: $Name"
            & $ApplyScript
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match '^SKIP:(.*)$') {
                # ApplyScript decided this host does not qualify (e.g. OS too old, no domain).
                # This is NOT a failure -- just a clean opt-out.
                $skipReason = $Matches[1].Trim()
                $applyStatus = 'NotApplicable'
                Write-Info "  Skipped: $skipReason"
                # Remove the backup entry that was just made -- nothing was changed.
                if ($global:Backup.Contains($ID)) { $global:Backup.Remove($ID) }
                $global:Skipped++
                $global:Checks.Add([PSCustomObject]@{
                    ID             = $ID
                    Category       = $Category
                    Name           = $Name
                    Description    = $Description
                    Severity       = $Severity
                    Compliant      = $null
                    ApplyStatus    = $applyStatus
                    CheckError     = ''
                    SkipReason     = $skipReason
                    Reference      = $Reference
                    Remediation    = $Remediation
                    RebootRequired = $RebootRequired
                })
                return
            }
            Write-Err "  Apply failed: $_"
            $applyStatus = "FAILED: $msg"
            $global:Failed++
            $applyThrew = $true
        }

        if (-not $applyThrew) {
            # Verify -- this is what determines Applied vs Applied-NotVerified
            $verifyOk = $false
            try { $verifyOk = & $CheckScript } catch { $verifyOk = $false }
            if ($verifyOk) {
                Write-Pass "  Verified OK"
                $applyStatus = 'Applied+Verified'
            } else {
                Write-Fail "  Applied but verify failed (may need reboot)"
                $applyStatus = 'Applied-NotVerified'
            }
            # Increment Applied only when we actually wrote something successfully.
            $global:Applied++
        }
    } elseif ($isApply -and $compliant) {
        $applyStatus = 'AlreadyCompliant'
        $global:Skipped++
    }

    # --- POST-APPLY RE-CHECK ---
    # Re-check after apply so the report reflects the post-apply state.
    if ($isApply -and $applyStatus -notin @('', 'AlreadyCompliant', 'NotApplicable')) {
        try {
            $compliant = & $CheckScript
        } catch {
            $compliant = $false
        }
    }

    $global:Checks.Add([PSCustomObject]@{
        ID             = $ID
        Category       = $Category
        Name           = $Name
        Description    = $Description
        Severity       = $Severity
        Compliant      = $compliant
        ApplyStatus    = $applyStatus
        CheckError     = $checkError
        SkipReason     = ''
        Reference      = $Reference
        Remediation    = $Remediation
        RebootRequired = $RebootRequired
    })
}

function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -EA Stop
        return $v.$Name
    } catch { return $Default }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { $null = New-Item -Path $Path -Force }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Backup-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -EA Stop
        return @{ Path = $Path; Name = $Name; Value = $v.$Name; Existed = $true }
    } catch {
        return @{ Path = $Path; Name = $Name; Value = $null; Existed = $false }
    }
}

# -------------------------------------------------------
# ROLLBACK MODE  (runs after flag resolution below)
# -------------------------------------------------------
function Invoke-Rollback {
    param([string]$BackupPath, [switch]$NonInteractive)

    Write-Phase "ROLLBACK MODE"

    # If no backup specified or path invalid -- offer interactive selection
    if ([string]::IsNullOrEmpty($BackupPath) -or -not (Test-Path $BackupPath)) {
        if (-not $NonInteractive) {
            $backupFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter 'HardeningBackup_*.json' -File |
                             Sort-Object LastWriteTime -Descending)
            if ($backupFiles.Count -eq 0) {
                Write-Err "No backup files found in: $PSScriptRoot"
                Write-Host "  Run Apply first to create a backup." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
                $null = [Console]::ReadLine()
                exit 1
            }
            $selected = $false
            while (-not $selected) {
                $sep = "  " + ("=" * 62)
                Write-Host ""
                Write-Host $sep -ForegroundColor DarkCyan
                Write-Host "    Select backup file to restore:" -ForegroundColor Cyan
                Write-Host $sep -ForegroundColor DarkCyan
                Write-Host ""
                for ($i = 0; $i -lt $backupFiles.Count; $i++) {
                    $f    = $backupFiles[$i]
                    $age  = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    $size = [math]::Round($f.Length / 1KB, 1)
                    Write-Host ("    [{0,2}]  {1}  [{2}]  {3} KB" -f ($i + 1), $f.Name, $age, $size) -ForegroundColor Gray
                }
                Write-Host ""
                Write-Host "    [0]   Back" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host $sep -ForegroundColor DarkCyan
                Write-Host ""
                $sel = [Console]::ReadLine()
                if ($sel.Trim() -eq '0') { return $false }   # signal caller to go back
                $selIdx = 0
                if ([int]::TryParse($sel.Trim(), [ref]$selIdx) -and $selIdx -ge 1 -and $selIdx -le $backupFiles.Count) {
                    $BackupPath = $backupFiles[$selIdx - 1].FullName
                    Write-Info "Selected: $BackupPath"
                    $selected = $true
                } else {
                    Write-Host "  Invalid selection, try again." -ForegroundColor Yellow
                }
            }
        } else {
            Write-Err "Backup file not found: $BackupPath"
            Write-Host "  Specify: -BackupPath C:\path\to\backup.json" -ForegroundColor Yellow
            exit 1
        }
    }

    $bkData  = Get-Content $BackupPath -Raw | ConvertFrom-Json
    $bkCount = 0
    $bkFail  = 0

    # Pre-flight: count operations and confirm
    $opCount = @($bkData.PSObject.Properties | Where-Object { $_.Name -notlike '_*' }).Count
    Write-Host ""
    Write-Host "  Backup contains $opCount setting(s) to restore" -ForegroundColor Cyan
    if (-not $NonInteractive) {
        Write-Host "  Continue with rollback? [Y/N]: " -ForegroundColor Yellow -NoNewline
        $rbConfirm = [Console]::ReadLine()
        if ($rbConfirm -notmatch '^[Yy]') {
            Write-Host "  Rollback aborted by user." -ForegroundColor Red
            return $true
        }
    }
    Write-Host ""

    foreach ($prop in $bkData.PSObject.Properties) {
        $id  = $prop.Name
        $bkv = $prop.Value

        if ($id -like '_*') { continue }

        try {
            # AUD-001..027: Audit policy
            if ($id -match '^AUD-0[0-2][0-9]$' -and $bkv.Subcategory) {
                $sub   = $bkv.Subcategory
                $prev  = $bkv.Setting
                $sFlag = if ($prev -match 'Success') { 'enable' } else { 'disable' }
                $fFlag = if ($prev -match 'Failure') { 'enable' } else { 'disable' }
                $guid  = if ($bkv.Guid) { $bkv.Guid } else { $sub }
                $ap    = "$env:SystemRoot\System32\auditpol.exe"
                $null  = & $ap /set /subcategory:"$guid" /success:$sFlag /failure:$fFlag 2>&1
                Write-Pass "Audit restored: $sub -> $prev"
                $bkCount++; continue
            }

            # Services: RemoteRegistry (NET-010), Spooler (SYS-008)
            if ($id -eq 'NET-010' -or $id -eq 'SYS-008') {
                $svcName = if ($id -eq 'NET-010') { 'RemoteRegistry' } else { 'Spooler' }
                if ($bkv.StartType) {
                    Set-Service $svcName -StartupType $bkv.StartType -EA SilentlyContinue
                    if ($bkv.Status -eq 'Running') { Start-Service $svcName -EA SilentlyContinue }
                    Write-Pass "Service restored: $svcName -> $($bkv.StartType)"
                    $bkCount++; continue
                }
            }

            # SYS-003: Firewall profiles
            if ($id -eq 'SYS-003') {
                $pfList = @($bkv)
                foreach ($pf in $pfList) {
                    if ($pf -and $pf.PSObject.Properties['Name']) {
                        Set-NetFirewallProfile -Name $pf.Name -Enabled $pf.Enabled -EA SilentlyContinue
                    }
                }
                Write-Pass "Firewall profiles restored"
                $bkCount++; continue
            }

            # SYS-005: DEP
            if ($id -eq 'SYS-005') {
                $depVal = if ($bkv.DEP) { $bkv.DEP } else { 'OptIn' }
                & bcdedit /set '{current}' nx $depVal 2>&1 | Out-Null
                Write-Pass "DEP restored -> $depVal  (reboot required)"
                $bkCount++; continue
            }

            # PS-004: PowerShell v2
            if ($id -eq 'PS-004') {
                $rootState = $null
                if ($bkv.PSObject.Properties['PSv2RootState']) {
                    $rootState = $bkv.PSv2RootState
                }
                if ($rootState -eq 'Enabled' -or $rootState -eq 'EnablePending') {
                    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -EA SilentlyContinue | Out-Null
                    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2'     -NoRestart -EA SilentlyContinue | Out-Null
                    Write-Pass "PSv2 re-enabled  (reboot required)"
                } else {
                    Write-Info "PSv2 was not enabled before -- nothing to restore"
                }
                $bkCount++; continue
            }

            # NET-007: NetBIOS adapter list -- new format: { Adapters = [{Path,Value},...] }
            if ($id -eq 'NET-007') {
                $adapters = $null
                if ($bkv.PSObject.Properties['Adapters']) {
                    $adapters = $bkv.Adapters
                } else {
                    # Legacy format: bkv is a hashtable-like object with adapter paths as property names
                    $adapters = @($bkv.PSObject.Properties | ForEach-Object {
                        [PSCustomObject]@{ Path = $_.Name; Value = $_.Value }
                    })
                }
                foreach ($adp in $adapters) {
                    if ($adp -and $adp.Path) {
                        Set-ItemProperty -Path $adp.Path -Name 'NetbiosOptions' -Value $adp.Value -Force -EA SilentlyContinue
                    }
                }
                Write-Pass "NetBIOS adapter options restored"
                $bkCount++; continue
            }

            # Composite entries (NET-005/006, CRED-006, etc)
            $isComposite = $false
            if ($bkv -is [System.Management.Automation.PSCustomObject]) {
                if ($null -ne $bkv.PSObject.Properties['Existed']) {
                    if ($bkv.Existed -eq $false) {
                        Remove-ItemProperty -Path $bkv.Path -Name $bkv.Name -EA SilentlyContinue
                        Write-Pass "Removed: ${id} ($($bkv.Name))"
                    } else {
                        if (-not (Test-Path $bkv.Path)) { $null = New-Item $bkv.Path -Force }
                        Set-ItemProperty -Path $bkv.Path -Name $bkv.Name -Value $bkv.Value -Force -EA SilentlyContinue
                        Write-Pass "Restored: ${id} = $($bkv.Value)"
                    }
                    $bkCount++; continue
                }
                $subEntries = @($bkv.PSObject.Properties | Where-Object {
                    $null -ne $_.Value -and
                    $_.Value -is [System.Management.Automation.PSCustomObject] -and
                    ($_.Value.PSObject.Properties.Name -contains 'Path') -and
                    ($_.Value.PSObject.Properties.Name -contains 'Name') })
                if ($subEntries.Count -gt 0) {
                    $isComposite = $true
                    foreach ($sp in $subEntries) {
                        $entry = $sp.Value
                        if (-not $entry.Path) { continue }
                        if ($entry.Existed -eq $false) {
                            Remove-ItemProperty -Path $entry.Path -Name $entry.Name -EA SilentlyContinue
                        } else {
                            if (-not (Test-Path $entry.Path)) { $null = New-Item $entry.Path -Force }
                            Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.Value -Force -EA SilentlyContinue
                        }
                    }

                    # NET-013 cleanup: if Apply created the IPv6 Parameters key (because the
                    # OS lacked it), remove the now-empty key so we leave no residue.
                    if ($id -eq 'NET-013' -and $bkv.PSObject.Properties['IPv6KeyExisted'] `
                            -and $bkv.IPv6KeyExisted -eq $false) {
                        $ipv6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
                        if (Test-Path $ipv6Key) {
                            $remaining = Get-Item $ipv6Key -EA SilentlyContinue
                            $valCount = if ($remaining) { @($remaining.Property).Count } else { 0 }
                            $subCount = @(Get-ChildItem $ipv6Key -EA SilentlyContinue).Count
                            if ($valCount -eq 0 -and $subCount -eq 0) {
                                Remove-Item -Path $ipv6Key -Force -EA SilentlyContinue
                                Write-Info "  Removed empty IPv6 Parameters key created during apply"
                            }
                        }
                    }

                    Write-Pass "Restored: ${id} (composite reg)"
                    $bkCount++; continue
                }
            }

            Write-Info "Skipped ${id}: unrecognized backup format"

        } catch {
            Write-Err "Rollback failed for ${id}: $($_.Exception.Message)"
            $bkFail++
        }
    }

    Write-Host ""
    if ($bkFail -eq 0) {
        Write-Host "  Rollback complete: $bkCount settings restored" -ForegroundColor Green
    } else {
        Write-Host "  Rollback complete: $bkCount restored, $bkFail failed" -ForegroundColor Yellow
    }
    Write-Host "  Backup file: $BackupPath" -ForegroundColor DarkGray
    Write-Host ""
    if (-not $NonInteractive) {
        Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
        $null = [Console]::ReadLine()
    }
    return $true
}

# -------------------------------------------------------
# BANNER
# -------------------------------------------------------
Write-Host ''
Write-Host '     ____                  _    ____            ' -ForegroundColor DarkCyan
Write-Host '    |_  /__ ___ _____ ___ | |_ / __/__ ___     ' -ForegroundColor Cyan
Write-Host '     / // _` \ V / -_)  _||  _\__ \/ -_) _|    ' -ForegroundColor Cyan
Write-Host '    /___\__,_|\_/\___\__| |_| |___/\___\__|    ' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '    ZavetSec-Harden v1.4    ' -ForegroundColor White
Write-Host '    Windows Security Hardening Baseline' -ForegroundColor Gray
Write-Host '    CIS Benchmark | DISA STIG | MS Security Baseline' -ForegroundColor DarkGray
Write-Host '    https://github.com/zavetsec                 ' -ForegroundColor DarkGray
Write-Host ''

# -------------------------------------------------------
# EARLY HEADER (admin check moved AFTER mode resolution)
# -------------------------------------------------------
Write-Host "  ============================================================" -ForegroundColor DarkCyan
Write-Host "    Script : ZavetSec-Harden v1.4" -ForegroundColor Cyan
Write-Host "    Mode   : $(if ($Mode) { $Mode } else { '(interactive)' })" -ForegroundColor Gray
Write-Host "    Host   : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "    Time   : $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  ============================================================" -ForegroundColor DarkCyan

# Compute admin status early but don't act on $isApply yet -- $isApply is resolved later
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ===========================================================
# MAIN MENU -- shown when no -Mode flag is given
# ===========================================================
if ($Mode -eq '' -and -not $NonInteractive) {
    # Loop until valid selection
    $modeSelected = $false
    while (-not $modeSelected) {
        $sep = "  " + ("=" * 62)
        Write-Host ""
        Write-Host $sep -ForegroundColor DarkCyan
        Write-Host "    Select operation mode:" -ForegroundColor Cyan
        Write-Host $sep -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "    [1]  Audit    " -NoNewline -ForegroundColor White
        Write-Host "- Check current state, no changes made" -ForegroundColor DarkGray
        Write-Host "    [2]  Apply    " -NoNewline -ForegroundColor Yellow
        Write-Host "- Harden the system (backup created first)" -ForegroundColor DarkGray
        Write-Host "    [3]  Rollback " -NoNewline -ForegroundColor Magenta
        Write-Host "- Revert to pre-hardening state from backup" -ForegroundColor DarkGray
        Write-Host "    [4]  Defaults " -NoNewline -ForegroundColor DarkYellow
        Write-Host "- Reset all settings to Windows out-of-box defaults" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    [0]  Exit" -ForegroundColor DarkGray
        Write-Host ""
        $modeChoice = [Console]::ReadLine()
        switch ($modeChoice.Trim()) {
            '1' { $Mode = 'Audit';    $modeSelected = $true }
            '2' { $Mode = 'Apply';    $modeSelected = $true }
            '3' { $Mode = 'Rollback'; $modeSelected = $true }
            '4' { $Mode = 'Defaults'; $modeSelected = $true }
            '0' { Write-Host "  Exiting." -ForegroundColor DarkGray; exit 0 }
            default {
                Write-Host "  Invalid choice, try again." -ForegroundColor Yellow
            }
        }
    }
} elseif ($Mode -eq '') {
    # NonInteractive with no Mode -- default to Audit
    $Mode = 'Audit'
}

# Resolve mode flags now that Mode is known
$isApply    = $Mode -eq 'Apply'
$isAudit    = $Mode -eq 'Audit'
$isRollback = $Mode -eq 'Rollback'
$isDefaults = $Mode -eq 'Defaults'

# -- Admin check (now that $isApply is resolved) -------------------------------
if (-not $isAdmin) {
    Write-Err "Not running as Administrator."
    if ($isApply -or $isDefaults) {
        Write-Host "  Apply/Defaults modes require elevation. Restart PowerShell as Administrator and re-run." -ForegroundColor Yellow
        if (-not $NonInteractive) {
            Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
            $null = [Console]::ReadLine()
        }
        exit 1
    }
    if ($isRollback) {
        Write-Host "  Rollback requires elevation to write to HKLM. Restart PowerShell as Administrator and re-run." -ForegroundColor Yellow
        if (-not $NonInteractive) {
            Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
            $null = [Console]::ReadLine()
        }
        exit 1
    }
    Write-Host "  Audit mode -- some checks may report inaccurately without admin rights." -ForegroundColor Yellow
}

# -- Apply-mode pre-flight: confirm + backup directory check ------------------
if ($isApply) {
    Write-Host ""
    Write-Host "  [APPLY MODE] Changes will be made to this system." -ForegroundColor Yellow
    Write-Host "  Backup will be saved to: $BackupPath" -ForegroundColor Cyan
    Write-Host ""

    # Validate / create backup directory early, before any changes
    $backupParent = Split-Path $BackupPath -Parent
    if ($backupParent -and -not (Test-Path $backupParent)) {
        try {
            $null = New-Item -Path $backupParent -ItemType Directory -Force -ErrorAction Stop
            Write-Host "  Created backup directory: $backupParent" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [!] Cannot create backup directory: $backupParent" -ForegroundColor Yellow
            Write-Host "  [!] Error: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "      Defaulting backup to TEMP folder" -ForegroundColor Yellow
            $BackupPath = Join-Path $env:TEMP "HardeningBackup_${env:COMPUTERNAME}_$_stamp.json"
        }
    }
    if ($NonInteractive) {
        Write-Host "  [-NonInteractive] Proceeding without confirmation." -ForegroundColor DarkGray
    } else {
        $confirm = Read-Host "  Continue? [Y/N]"
        if ($confirm -notmatch '^[Yy]') { Write-Host "  Aborted." -ForegroundColor Red; exit 0 }
    }
}

# -- Update console header with resolved mode
Write-Host "  ============================================================" -ForegroundColor DarkCyan
Write-Host "    Mode   : $Mode" -ForegroundColor $(if ($isApply) { 'Yellow' } elseif ($isRollback) { 'Magenta' } elseif ($isDefaults) { 'DarkYellow' } else { 'Cyan' })
Write-Host "  ============================================================" -ForegroundColor DarkCyan
Write-Host ""

# -- Handle Rollback mode ------------------------------------------------------
if ($isRollback) {
    $result = Invoke-Rollback -BackupPath $BackupPath -NonInteractive:$NonInteractive
    if ($result -eq $false) {
        # User pressed Back from backup selection -- restart from main menu
        # Re-enter mode loop
        $modeSelected = $false
        while (-not $modeSelected) {
            $sep = "  " + ("=" * 62)
            Write-Host ""
            Write-Host $sep -ForegroundColor DarkCyan
            Write-Host "    Select operation mode:" -ForegroundColor Cyan
            Write-Host $sep -ForegroundColor DarkCyan
            Write-Host ""
            Write-Host "    [1]  Audit    " -NoNewline -ForegroundColor White
            Write-Host "- Check current state, no changes made" -ForegroundColor DarkGray
            Write-Host "    [2]  Apply    " -NoNewline -ForegroundColor Yellow
            Write-Host "- Harden the system (backup created first)" -ForegroundColor DarkGray
            Write-Host "    [3]  Rollback " -NoNewline -ForegroundColor Magenta
            Write-Host "- Revert to pre-hardening state from backup" -ForegroundColor DarkGray
            Write-Host "    [4]  Defaults " -NoNewline -ForegroundColor DarkYellow
            Write-Host "- Reset all settings to Windows out-of-box defaults" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "    [0]  Exit" -ForegroundColor DarkGray
            Write-Host ""
            $modeChoice = [Console]::ReadLine()
            switch ($modeChoice.Trim()) {
                '1' { $Mode = 'Audit';    $isAudit = $true;  $isApply = $false; $isRollback = $false; $isDefaults = $false; $modeSelected = $true }
                '2' { $Mode = 'Apply';    $isApply = $true;  $isAudit = $false; $isRollback = $false; $isDefaults = $false; $modeSelected = $true }
                '3' {
                    $Mode = 'Rollback'; $isRollback = $true; $isApply = $false; $isAudit = $false; $isDefaults = $false
                    $result = Invoke-Rollback -BackupPath '' -NonInteractive:$NonInteractive
                    if ($result -ne $false) { exit 0 }
                    # else loop again
                }
                '4' { $Mode = 'Defaults'; $isDefaults = $true; $isApply = $false; $isAudit = $false; $isRollback = $false; $modeSelected = $true }
                '0' { Write-Host "  Exiting." -ForegroundColor DarkGray; exit 0 }
                default { Write-Host "  Invalid choice, try again." -ForegroundColor Yellow }
            }
        }
    } else {
        exit 0
    }
}

# -- Handle Defaults mode ------------------------------------------------------
if ($isDefaults) {
    $defaultsScript = Join-Path $PSScriptRoot 'WindowsDefaults.ps1'
    if (-not (Test-Path $defaultsScript)) {
        Write-Err "WindowsDefaults.ps1 not found in: $PSScriptRoot"
        Write-Host "  Place WindowsDefaults.ps1 in the same folder as this script." -ForegroundColor Yellow
        Write-Host ""
        if (-not $NonInteractive) {
            Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
            $null = [Console]::ReadLine()
        }
        exit 1
    }

    # Security: verify that WindowsDefaults.ps1 is owned by an admin principal.
    # Defends against an unprivileged user dropping a malicious WindowsDefaults.ps1
    # next to this script and waiting for an admin to run it.
    $ownerOk = $false
    try {
        $acl = Get-Acl -Path $defaultsScript -ErrorAction Stop
        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        # Trusted owners: BUILTIN\Administrators (S-1-5-32-544), SYSTEM (S-1-5-18),
        # TrustedInstaller (S-1-5-80-...), or any account in Domain Admins / Enterprise Admins.
        $trustedSids = @('S-1-5-32-544','S-1-5-18')
        if ($trustedSids -contains $ownerSid.Value) { $ownerOk = $true }
        if ($ownerSid.Value -match '^S-1-5-21-.*-512$') { $ownerOk = $true }   # Domain Admins
        if ($ownerSid.Value -match '^S-1-5-21-.*-519$') { $ownerOk = $true }   # Enterprise Admins
        # Also accept current user if they themselves are an Administrator (interactive use).
        $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User
        if ($ownerSid.Value -eq $currentSid.Value -and $isAdmin) { $ownerOk = $true }
    } catch {
        Write-Err "Could not read ACL of $defaultsScript -- aborting for safety."
        exit 1
    }

    if (-not $ownerOk) {
        Write-Err "WindowsDefaults.ps1 is NOT owned by an administrator (owner SID: $($ownerSid.Value))."
        Write-Err "Refusing to execute: this could be a planted file. Re-take ownership or replace the script."
        Write-Host "  takeown /F `"$defaultsScript`"" -ForegroundColor Yellow
        if (-not $NonInteractive) {
            Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
            $null = [Console]::ReadLine()
        }
        exit 1
    }

    if ($NonInteractive) {
        & $defaultsScript -NonInteractive
    } else {
        & $defaultsScript
    }
    exit 0
}

# ===========================================================
# DEVICE PROFILE SELECTION
# ===========================================================
# Each profile sets Skip* flags that are unsafe for that device type.
# 'All'    = nothing skipped, apply everything (operator responsibility).
# 'Custom' = use -Skip* flags passed on command line (default).
# ---------------------------------------------------------------

function Show-ProfileMenu {
    $sep = "  " + ("=" * 62)
    Write-Host ""
    Write-Host $sep -ForegroundColor DarkCyan
    Write-Host "    Select device profile:" -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "    [1]  Workstation       " -NoNewline -ForegroundColor White
    Write-Host "- endpoint, full hardening applied" -ForegroundColor DarkGray
    Write-Host "    [2]  File Server       " -NoNewline -ForegroundColor White
    Write-Host "- SMBv1/signing critical, skip Credential Guard" -ForegroundColor DarkGray
    Write-Host "    [3]  Domain Controller " -NoNewline -ForegroundColor White
    Write-Host "- skip Credential Guard + audit policy (use GPO)" -ForegroundColor DarkGray
    Write-Host "    [4]  RDS               " -NoNewline -ForegroundColor White
    Write-Host "- terminal server, full hardening + transcription note" -ForegroundColor DarkGray
    Write-Host "    [5]  SQL / DB Server   " -NoNewline -ForegroundColor White
    Write-Host "- skip Credential Guard, check Remote Registry" -ForegroundColor DarkGray
    Write-Host "    [6]  Exchange / Mail   " -NoNewline -ForegroundColor White
    Write-Host "- skip network + credential sections (NTLM/SMB deps)" -ForegroundColor DarkGray
    Write-Host "    [7]  Print Server      " -NoNewline -ForegroundColor White
    Write-Host "- Print Spooler preserved, skip Credential Guard" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [8]  ALL               " -NoNewline -ForegroundColor Yellow
    Write-Host "- apply all 60 checks, operator takes full responsibility" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [0]  Back              " -NoNewline -ForegroundColor DarkGray
    Write-Host "- return to mode selection" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $sep -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-ProfileSummary {
    param(
        [string]   $ProfileName,
        [string[]] $Applied,
        [string[]] $Skipped,
        [string]   $Notes
    )
    $sep = "  " + ("-" * 62)
    Write-Host ""
    Write-Host "  Profile : " -NoNewline -ForegroundColor DarkGray
    Write-Host $ProfileName -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor DarkGray
    foreach ($item in $Applied) {
        Write-Host "  [APPLY]  $item" -ForegroundColor Green
    }
    foreach ($item in $Skipped) {
        Write-Host "  [SKIP ]  $item" -ForegroundColor Yellow
    }
    if ($Notes) {
        Write-Host $sep -ForegroundColor DarkGray
        Write-Host "  NOTE: $Notes" -ForegroundColor DarkGray
    }
    Write-Host $sep -ForegroundColor DarkGray
    Write-Host ""
}

# ---------------------------------------------------------------
# Show interactive menu when Mode=Apply and no profile specified
# ---------------------------------------------------------------
if ($isApply -and $DeviceProfile -eq 'Custom' -and -not $NonInteractive) {
    $profileSelected = $false
    while (-not $profileSelected) {
        Show-ProfileMenu
        $profileChoice = [Console]::ReadLine()
        switch ($profileChoice.Trim()) {
            '1' { $DeviceProfile = 'Workstation';     $profileSelected = $true }
            '2' { $DeviceProfile = 'FileServer';      $profileSelected = $true }
            '3' { $DeviceProfile = 'DomainController'; $profileSelected = $true }
            '4' { $DeviceProfile = 'RDS';             $profileSelected = $true }
            '5' { $DeviceProfile = 'SQL';             $profileSelected = $true }
            '6' { $DeviceProfile = 'Exchange';        $profileSelected = $true }
            '7' { $DeviceProfile = 'PrintServer';     $profileSelected = $true }
            '8' { $DeviceProfile = 'All';             $profileSelected = $true }
            '0' {
                # Back -- re-run mode selection
                Write-Host "  Going back to mode selection..." -ForegroundColor DarkGray
                $modeSelected = $false
                while (-not $modeSelected) {
                    $sep = "  " + ("=" * 62)
                    Write-Host ""
                    Write-Host $sep -ForegroundColor DarkCyan
                    Write-Host "    Select operation mode:" -ForegroundColor Cyan
                    Write-Host $sep -ForegroundColor DarkCyan
                    Write-Host ""
                    Write-Host "    [1]  Audit    " -NoNewline -ForegroundColor White
                    Write-Host "- Check current state, no changes made" -ForegroundColor DarkGray
                    Write-Host "    [2]  Apply    " -NoNewline -ForegroundColor Yellow
                    Write-Host "- Harden the system (backup created first)" -ForegroundColor DarkGray
                    Write-Host "    [3]  Rollback " -NoNewline -ForegroundColor Magenta
                    Write-Host "- Revert to pre-hardening state from backup" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "    [0]  Exit" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host $sep -ForegroundColor DarkCyan
                    Write-Host ""
                    $modeChoice = [Console]::ReadLine()
                    switch ($modeChoice.Trim()) {
                        '1' {
                            $Mode = 'Audit'
                            $isApply = $false; $isAudit = $true; $isRollback = $false
                            $profileSelected = $true; $modeSelected = $true
                        }
                        '2' {
                            $Mode = 'Apply'
                            $isApply = $true; $isAudit = $false; $isRollback = $false
                            $modeSelected = $true
                            # stays in profile loop
                        }
                        '3' {
                            $Mode = 'Rollback'
                            $isApply = $false; $isAudit = $false; $isRollback = $true
                            $profileSelected = $true; $modeSelected = $true
                        }
                        '0' { Write-Host "  Exiting." -ForegroundColor DarkGray; exit 0 }
                        default { Write-Host "  Invalid choice, try again." -ForegroundColor Yellow }
                    }
                }
            }
            default {
                Write-Host "  Invalid choice, try again." -ForegroundColor Yellow
            }
        }
    }
}

# ---------------------------------------------------------------
# Apply profile -- configure Skip* flags for selected device role
# ---------------------------------------------------------------
switch ($DeviceProfile) {

    'Workstation' {
        $a = @(
            'Network Hardening    (NET-001..010)',
            'Credential Protection (CRED-001..006) incl. Credential Guard',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010)'
        )
        Show-ProfileSummary 'Workstation' $a @() ''
    }

    'FileServer' {
        $SkipCredentialProtection = $true
        $a = @(
            'Network Hardening    (NET-001..010) -- SMBv1 off, signing required',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010)'
        )
        $s = @(
            'Credential Protection (CRED-001..006) -- Credential Guard unstable on some storage HW'
        )
        Show-ProfileSummary 'FileServer' $a $s 'Before Apply: Get-SmbSession | Where-Object Dialect -eq 1.0'
    }

    'DomainController' {
        $SkipCredentialProtection = $true
        $SkipAuditPolicy          = $true
        $a = @(
            'Network Hardening    (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'System Hardening     (SYS-001..010)'
        )
        $s = @(
            'Credential Protection -- Credential Guard not supported on DC (Microsoft KB)',
            'Audit Policy          -- manage via Default Domain Controllers Policy (GPO)'
        )
        Show-ProfileSummary 'DomainController' $a $s 'Manage audit via GPO; align with AUD-029 (SCENoApplyLegacyAuditPolicy)'
    }

    'RDS' {
        $a = @(
            'Network Hardening    (NET-001..010)',
            'Credential Protection (CRED-001..006)',
            'PowerShell Hardening (PS-001..005) -- transcription enabled',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010)'
        )
        Show-ProfileSummary 'RDS' $a @() 'PS-003: on busy RDS C:\ProgramData\PSTranscripts grows fast -- configure rotation'
    }

    'SQL' {
        $SkipCredentialProtection = $true
        $a = @(
            'Network Hardening    (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010)'
        )
        $s = @(
            'Credential Protection -- Credential Guard unsupported on SQL Server (some configs)'
        )
        Show-ProfileSummary 'SQL' $a $s 'Check NET-010 (Remote Registry): some SQL monitoring tools rely on it'
    }

    'Exchange' {
        $SkipNetworkHardening     = $true
        $SkipCredentialProtection = $true
        $a = @(
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010)'
        )
        $s = @(
            'Network Hardening    -- Exchange depends on specific NTLM/SMB settings',
            'Credential Protection -- Credential Guard incompatible with Exchange'
        )
        Show-ProfileSummary 'Exchange' $a $s 'Recommended: run Audit first, then apply sections manually'
    }

    'PrintServer' {
        $SkipCredentialProtection  = $true
        $EnablePrintSpoolerDisable = $false
        $a = @(
            'Network Hardening    (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010) -- Print Spooler PRESERVED'
        )
        $s = @(
            'Credential Protection          -- skipped',
            'SYS-008 Print Spooler Disable  -- forced OFF (this is a print server)'
        )
        Show-ProfileSummary 'PrintServer' $a $s ''
    }

    'All' {
        $SkipAuditPolicy           = $false
        $SkipNetworkHardening      = $false
        $SkipPowerShell            = $false
        $SkipCredentialProtection  = $false
        $EnablePrintSpoolerDisable = $true
        $a = @(
            'Network Hardening    (NET-001..010)',
            'Credential Protection (CRED-001..006) incl. Credential Guard',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy         (AUD-001..029)',
            'System Hardening     (SYS-001..010) + Print Spooler DISABLED'
        )
        Show-ProfileSummary 'ALL' $a @() 'WARNING: applies all 60 checks incl. Credential Guard and Print Spooler disable'
        Write-Host "  [!!] Profile ALL selected. Press ENTER to confirm or Ctrl+C to abort." -ForegroundColor Red
        $null = [Console]::ReadLine()
    }

    'Custom' {
        Write-Info 'Profile: Custom (manual -Skip* flags)'
    }
}

# -- Active flags summary ------------------------------------------------------
if ($isApply -and $DeviceProfile -ne 'Custom') {
    Write-Host "  Active flags:" -ForegroundColor DarkGray
    Write-Host "    SkipNetwork     : $SkipNetworkHardening"     -ForegroundColor $(if ($SkipNetworkHardening)     { 'Yellow' } else { 'DarkGray' })
    Write-Host "    SkipCredentials : $SkipCredentialProtection"  -ForegroundColor $(if ($SkipCredentialProtection)  { 'Yellow' } else { 'DarkGray' })
    Write-Host "    SkipPowerShell  : $SkipPowerShell"           -ForegroundColor $(if ($SkipPowerShell)           { 'Yellow' } else { 'DarkGray' })
    Write-Host "    SkipAuditPolicy : $SkipAuditPolicy"          -ForegroundColor $(if ($SkipAuditPolicy)          { 'Yellow' } else { 'DarkGray' })
    Write-Host "    DisableSpooler  : $EnablePrintSpoolerDisable"  -ForegroundColor $(if ($EnablePrintSpoolerDisable)  { 'Cyan'   } else { 'DarkGray' })
    Write-Host ""
}

# -- Build profile summary strings for HTML report ----------------------------
# Describes which sections were applied/skipped and why.
# Used in the HTML report section 02.5 (Device Profile Summary).
$global:ProfileApplied = [System.Collections.Generic.List[string]]::new()
$global:ProfileSkipped = [System.Collections.Generic.List[string]]::new()
$global:ProfileNote    = ''

switch ($DeviceProfile) {
    'Workstation' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'Credential Protection (CRED-001..006) including Credential Guard',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileNote = 'Full hardening applied. Safest profile for domain-joined and standalone workstations.'
    }
    'FileServer' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010) -- SMBv1 disabled, signing required',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileSkipped.AddRange([string[]]@(
            'Credential Protection (CRED-001..006) -- Credential Guard can cause instability on some storage hardware configurations'
        ))
        $global:ProfileNote = 'Verify no SMBv1 clients before applying: Get-SmbSession | Where-Object Dialect -eq 1.0'
    }
    'DomainController' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileSkipped.AddRange([string[]]@(
            'Credential Protection (CRED-001..006) -- Credential Guard is not supported on Domain Controllers per Microsoft documentation',
            'Audit Policy (AUD-001..029) -- audit policy on DCs should be managed via Default Domain Controllers Policy (GPO) to prevent conflicts'
        ))
        $global:ProfileNote = 'Manage audit policy via GPO. Ensure AUD-029 (SCENoApplyLegacyAuditPolicy) is set in GPO to prevent subcategory override.'
    }
    'RDS' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'Credential Protection (CRED-001..006)',
            'PowerShell Hardening (PS-001..005) -- transcription enabled',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileNote = 'PS-003 (transcription): on busy RDS hosts C:\ProgramData\PSTranscripts grows rapidly with concurrent sessions. Configure log rotation or redirect to a network path via GPO.'
    }
    'SQL' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileSkipped.AddRange([string[]]@(
            'Credential Protection (CRED-001..006) -- Credential Guard is unsupported or problematic on SQL Server in certain hardware and version configurations'
        ))
        $global:ProfileNote = 'Verify NET-010 (Remote Registry): some SQL Server monitoring agents use Remote Registry for metrics collection.'
    }
    'Exchange' {
        $global:ProfileApplied.AddRange([string[]]@(
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010)'
        ))
        $global:ProfileSkipped.AddRange([string[]]@(
            'Network Hardening (NET-001..010) -- Exchange Server has dependencies on specific NTLM and SMB configurations that SMB signing and NTLMv2-only settings can break',
            'Credential Protection (CRED-001..006) -- Credential Guard is incompatible with Exchange Server transport and authentication stack'
        ))
        $global:ProfileNote = 'Exchange requires individual analysis before hardening. Run Audit first, review all FAIL items, then apply sections manually after validating each dependency.'
    }
    'PrintServer' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010) -- Print Spooler service preserved'
        ))
        $global:ProfileSkipped.AddRange([string[]]@(
            'Credential Protection (CRED-001..006) -- skipped as a precaution on print server hardware',
            'SYS-008 Print Spooler Disable -- forced OFF: this host is a print server'
        ))
        $global:ProfileNote = 'SYS-008 is never applied on this profile regardless of -EnablePrintSpoolerDisable flag.'
    }
    'All' {
        $global:ProfileApplied.AddRange([string[]]@(
            'Network Hardening (NET-001..010)',
            'Credential Protection (CRED-001..006) including Credential Guard',
            'PowerShell Hardening (PS-001..005)',
            'Audit Policy (AUD-001..029)',
            'System Hardening (SYS-001..010) + Print Spooler disabled'
        ))
        $global:ProfileNote = 'ALL profile: every check applied. Operator confirmed full responsibility. Review report for any Applied-NotVerified items that require reboot.'
    }
    default {
        $global:ProfileNote = 'Custom profile: manual -Skip* flags used. See active flags in Coverage panel.'
    }
}


# SECTION 1: NETWORK HARDENING
# ===========================================================
if (-not $SkipNetworkHardening) {

Write-Phase "NETWORK PROTOCOLS"

# --- LLMNR ---
Test-And-Set -ID 'NET-001' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable LLMNR' `
    -Description 'LLMNR (Link-Local Multicast Name Resolution) can be abused for MITM credential capture (Responder)' `
    -Reference 'CIS L1 18.5.4.2 | MITRE T1557.001' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 99
        return $v -eq 0
    } `
    -BackupScript {
        Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    }

# --- mDNS ---
Test-And-Set -ID 'NET-002' -Category 'Network' -Severity 'MEDIUM' `
    -Name 'Disable mDNS' `
    -Description 'mDNS can be abused for network enumeration and MITM attacks' `
    -Reference 'CIS L2' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMDNS /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 99
        return $v -eq 0
    } `
    -BackupScript {
        Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS'
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 0
    }

# --- WPAD ---
Test-And-Set -ID 'NET-003' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable WPAD auto-detection' `
    -Description 'WPAD can be abused to proxy all HTTP traffic through attacker-controlled proxy' `
    -Reference 'MITRE T1557' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DisableWpad /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 99
        return $v -eq 1
    } `
    -BackupScript {
        Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 1
        # Disable WPAD service so the WinHTTP component cannot perform DHCP/DNS auto-discovery
        $svc = Get-Service 'WinHttpAutoProxySvc' -EA SilentlyContinue
        if ($svc) {
            Stop-Service 'WinHttpAutoProxySvc' -Force -EA SilentlyContinue
            Set-Service  'WinHttpAutoProxySvc' -StartupType Disabled -EA SilentlyContinue
        }
    }

# --- SMBv1 ---
Test-And-Set -ID 'NET-004' -Category 'Network' -Severity 'CRITICAL' `
    -Name 'Disable SMBv1' `
    -Description 'SMBv1 is vulnerable to EternalBlue (MS17-010/WannaCry/NotPetya). Must be disabled.' `
    -Reference 'CIS L1 | MS KB2696547 | MITRE T1210' `
    -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Set-ItemProperty HKLM:\SYSTEM\CCS\Services\LanmanServer\Parameters SMB1 0; Set-ItemProperty HKLM:\SYSTEM\CCS\Services\mrxsmb10 Start 4' `
    -CheckScript {
        # Server side
        $srvKey = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 99
        # Client side
        $cliKey = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 99
        return ($srvKey -eq 0) -and ($cliKey -eq 4)
    } `
    -BackupScript {
        @{
            Server = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
            Client = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start')
        }
    } `
    -ApplyScript {
        # Server
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
        # Client driver - disable
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4
        # Also via Set-SmbServerConfiguration if available
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -EA SilentlyContinue
        # Disable SMB1 feature
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -EA SilentlyContinue
    } -RebootRequired 'Yes'

# --- SMB Signing (Server) ---
Test-And-Set -ID 'NET-005' -Category 'Network' -Severity 'HIGH' `
    -Name 'Require SMB Signing (Server)' `
    -Description 'Without SMB signing, relay attacks (NTLM relay/Pass-the-Hash) are possible' `
    -Reference 'CIS L1 | MITRE T1557.001' `
    -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force' `
    -CheckScript {
        $req   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 99
        $enable= Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature'  99
        return ($req -eq 1) -and ($enable -eq 1)
    } `
    -BackupScript {
        @{
            Req    = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature')
            Enable = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature')
        }
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature'  1
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -EA SilentlyContinue
    }

# --- SMB Signing (Client) ---
Test-And-Set -ID 'NET-006' -Category 'Network' -Severity 'HIGH' `
    -Name 'Require SMB Signing (Client)' `
    -Description 'Client-side SMB signing prevents NTLM relay via captured traffic' `
    -Reference 'CIS L1 | MITRE T1557.001' `
    -Remediation 'Set-ItemProperty HKLM:\SYSTEM\CCS\Services\LanmanWorkstation\Parameters RequireSecuritySignature 1' `
    -CheckScript {
        $req = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 99
        return $req -eq 1
    } `
    -BackupScript {
        Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'  1
    }

# --- NBT-NS (NetBIOS Name Service) ---
Test-And-Set -ID 'NET-007' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable NetBIOS over TCP/IP (NBT-NS)' `
    -Description 'NBT-NS broadcast name resolution is abused by Responder for MITM attacks' `
    -Reference 'MITRE T1557.001' `
    -Remediation 'Get-ChildItem HKLM:\SYSTEM\CCS\Services\NetBT\Parameters\Interfaces | ForEach-Object { Set-ItemProperty $_.PSPath NetbiosOptions 2 }' `
    -CheckScript {
        $compliant = $true
        $adapters  = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue
        foreach ($a in $adapters) {
            $val = Get-RegValue $a.PSPath 'NetbiosOptions' 99
            # 2 = Disable NetBIOS; 0 = Default (DHCP); 1 = Enable
            if ($val -ne 2) { $compliant = $false; break }
        }
        return $compliant
    } `
    -BackupScript {
        $bkList = New-Object System.Collections.ArrayList
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | ForEach-Object {
            $val = Get-RegValue $_.PSPath 'NetbiosOptions' 0
            $null = $bkList.Add([PSCustomObject]@{
                Path  = $_.PSPath
                Value = $val
            })
        }
        return @{ Adapters = $bkList.ToArray() }
    } `
    -ApplyScript {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | ForEach-Object {
            Set-RegValue $_.PSPath 'NetbiosOptions' 2
        }
    }

# --- LMHOSTS lookup ---
Test-And-Set -ID 'NET-008' -Category 'Network' -Severity 'LOW' `
    -Name 'Disable LMHOSTS lookup' `
    -Description 'LMHOSTS file lookup is an unnecessary legacy name resolution method' `
    -Reference 'CIS L2' `
    -Remediation 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v EnableLMHOSTS /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'EnableLMHOSTS' 99
        return $v -eq 0
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'EnableLMHOSTS' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'EnableLMHOSTS' 0 }

# --- Anonymous Enumeration ---
Test-And-Set -ID 'NET-009' -Category 'Network' -Severity 'HIGH' `
    -Name 'Restrict anonymous enumeration of SAM accounts and shares' `
    -Description 'Prevents unauthenticated enumeration of users, groups, and shares' `
    -Reference 'CIS L1 2.3.10.2 | MITRE T1087' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f && reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v1 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 99
        $v2 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 99
        # On Vista+ only 0 and 1 are valid for these values; 2 was a legacy NT4/2000 setting.
        return ($v1 -eq 1) -and ($v2 -eq 1)
    } `
    -BackupScript {
        @{
            SAM = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM')
            All = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous')
        }
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'    1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0
    }

# --- Remote Registry ---
Test-And-Set -ID 'NET-010' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable Remote Registry service' `
    -Description 'Remote Registry allows remote modification of registry; major attack surface' `
    -Reference 'CIS L1' `
    -Remediation 'Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled' `
    -CheckScript {
        $svc = Get-Service 'RemoteRegistry' -EA SilentlyContinue
        if (-not $svc) { return $true }  # service absent = compliant by definition
        return ($svc.StartType -eq 'Disabled') -and ($svc.Status -eq 'Stopped')
    } `
    -BackupScript {
        $svc = Get-Service 'RemoteRegistry' -EA SilentlyContinue
        if (-not $svc) { return @{ StartType = 'Absent'; Status = 'Absent' } }
        return @{ StartType = $svc.StartType.ToString(); Status = $svc.Status.ToString() }
    } `
    -ApplyScript {
        $svc = Get-Service 'RemoteRegistry' -EA SilentlyContinue
        if (-not $svc) { return }
        Stop-Service 'RemoteRegistry' -Force -EA SilentlyContinue
        Set-Service  'RemoteRegistry' -StartupType Disabled -EA SilentlyContinue
    }


# --- Restrict Remote SAM (domain-safe: read-only for Admins only) ---
Test-And-Set -ID 'NET-011' -Category 'Network' -Severity 'HIGH' `
    -Name 'Restrict remote SAM enumeration to Administrators' `
    -Description 'Prevents non-admin accounts from querying SAM remotely (user/group enumeration, Pass-the-Hash recon). Safe on domain -- does not break DC or management tools that run as Admin.' `
    -Reference 'CIS L1 2.3.10.9 | MITRE T1087.001' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v RestrictRemoteSam /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSam' ''
        return $v -eq 'O:BAG:BAD:(A;;RC;;;BA)'
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSam' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSam' 'O:BAG:BAD:(A;;RC;;;BA)' -Type String }

# --- Null Session Pipes + Shares (clear anonymous access lists) ---
Test-And-Set -ID 'NET-012' -Category 'Network' -Severity 'MEDIUM' `
    -Name 'Clear anonymous null-session pipes and shares' `
    -Description 'Removes legacy lists of named pipes and shares accessible without authentication. Safe on domain -- modern DCs do not rely on null-session pipes.' `
    -Reference 'CIS L1 2.3.10.5 / 2.3.10.6' `
    -Remediation 'Set-ItemProperty HKLM:\SYSTEM\CCS\Services\LanManServer\Parameters NullSessionPipes "" && NullSessionShares ""' `
    -CheckScript {
        $pipes  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionPipes'  $null
        $shares = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionShares' $null
        $pipesOk  = ($null -eq $pipes)  -or ($pipes  -is [array] -and $pipes.Count  -eq 0) -or ($pipes  -eq '')
        $sharesOk = ($null -eq $shares) -or ($shares -is [array] -and $shares.Count -eq 0) -or ($shares -eq '')
        return $pipesOk -and $sharesOk
    } `
    -BackupScript {
        @{
            Pipes  = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionPipes')
            Shares = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionShares')
        }
    } `
    -ApplyScript {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
            -Name 'NullSessionPipes'  -Value ([string[]]@()) -Type MultiString -Force
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
            -Name 'NullSessionShares' -Value ([string[]]@()) -Type MultiString -Force
    }

# --- Disable IP Source Routing (IPv4 + IPv6) ---
Test-And-Set -ID 'NET-013' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable IP Source Routing (IPv4 + IPv6)' `
    -Description 'IP source routing can be abused for spoofing and routing bypass attacks. Disabling is safe on all domain and standalone configs.' `
    -Reference 'CIS L1 | MITRE T1557' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f  (repeat for Tcpip6)' `
    -CheckScript {
        $v4 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'  'DisableIPSourceRouting' 0
        $v6 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 0
        return ($v4 -eq 2) -and ($v6 -eq 2)
    } `
    -BackupScript {
        @{
            IPv4         = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'  'DisableIPSourceRouting')
            IPv6         = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting')
            # Track whether we are about to create the IPv6 Parameters key. If we created
            # it, rollback should remove the (now empty) key it would otherwise leave behind.
            IPv6KeyExisted = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters')
        }
    } `
    -ApplyScript {
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'  'DisableIPSourceRouting' 2
        # Ensure key exists for IPv6
        if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters')) {
            $null = New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Force
        }
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2
    }

# --- Disable ICMP Redirect ---
Test-And-Set -ID 'NET-014' -Category 'Network' -Severity 'HIGH' `
    -Name 'Disable ICMP Redirect acceptance' `
    -Description 'ICMP redirects can be used to poison routing tables and redirect traffic through attacker-controlled hosts.' `
    -Reference 'CIS L1 | MITRE T1557' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 99
        return $v -eq 0
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0 }

} # end SkipNetworkHardening

# ===========================================================
# SECTION 2: CREDENTIAL PROTECTION
# ===========================================================
if (-not $SkipCredentialProtection) {

Write-Phase "CREDENTIAL PROTECTION"

# --- WDigest ---
Test-And-Set -ID 'CRED-001' -Category 'Credentials' -Severity 'CRITICAL' `
    -Name 'Disable WDigest plaintext credential caching' `
    -Description 'WDigest caches credentials in plaintext in LSASS memory, readable by Mimikatz' `
    -Reference 'MS KB2871997 | MITRE T1003.001' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 99
        return $v -eq 0
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }

# --- LSA Protection (PPL) ---
Test-And-Set -ID 'CRED-002' -Category 'Credentials' -Severity 'CRITICAL' `
    -Name 'Enable LSA Protection (RunAsPPL)' `
    -Description 'Protected Process Light prevents unauthorized code injection into LSASS (anti-Mimikatz)' `
    -Reference 'MS KB3033929 | MITRE T1003.001' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f  (requires reboot)' `
    -RebootRequired 'Yes' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 }

# --- Credential Guard ---
Test-And-Set -ID 'CRED-003' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Enable Windows Defender Credential Guard' `
    -Description 'Credential Guard uses VBS to protect NTLM hashes and Kerberos tickets from extraction. Compliance verified via Win32_DeviceGuard.SecurityServicesRunning -- policy-bits alone are NOT sufficient (CG only activates after reboot if hardware supports VBS+SecureBoot+UEFI).' `
    -Reference 'MITRE T1003 | Requires UEFI + Secure Boot + VBS' `
    -Remediation 'GPO: Computer Config > Admin Templates > System > Device Guard > Turn On VBS + Credential Guard (LsaCfgFlags=1). Requires UEFI + Secure Boot. Verify post-reboot: (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning -contains 1' `
    -RebootRequired 'Yes' `
    -CheckScript {
        # Two-tier check: (1) policy-bits set, (2) actual runtime status via WMI.
        # Runtime status is the real source of truth. Policy alone returns NotVerified after apply.
        $lsaCfg = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 99
        $vbsEnab = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 99
        $policyOk = ($lsaCfg -ge 1) -and ($vbsEnab -eq 1)

        # Runtime check -- only present on Win10/Server 2016+ with DG namespace
        $runtimeOk = $false
        try {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                                  -ClassName  'Win32_DeviceGuard' -ErrorAction Stop
            if ($dg -and $dg.SecurityServicesRunning) {
                # SecurityServicesRunning: 1 = CG, 2 = HVCI
                $runtimeOk = ($dg.SecurityServicesRunning -contains 1)
            }
        } catch { $runtimeOk = $false }

        # Compliant only if BOTH policy is set AND runtime confirms CG running
        return $policyOk -and $runtimeOk
    } `
    -BackupScript {
        @{
            LsaCfgFlags = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags')
            VBS         = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity')
            CGPlatform  = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags')
            ReqPlatform = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'RequirePlatformSecurityFeatures')
            HVCI        = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'HypervisorEnforcedCodeIntegrity')
        }
    } `
    -ApplyScript {
        # Pre-flight: refuse to apply if hardware does not support VBS at all
        $vbsCapable = $false
        try {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                                  -ClassName  'Win32_DeviceGuard' -ErrorAction Stop
            if ($dg -and $dg.AvailableSecurityProperties) {
                # 1 = base virtualization support is present
                $vbsCapable = ($dg.AvailableSecurityProperties -contains 1)
            }
        } catch { $vbsCapable = $false }

        if (-not $vbsCapable) {
            Write-Fail "  Credential Guard: hardware does not advertise VBS support; skipping policy write"
            throw "VBS unsupported -- check UEFI/SecureBoot/IOMMU in firmware"
        }

        $dgKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        if (-not (Test-Path $dgKey)) { $null = New-Item $dgKey -Force }
        Set-RegValue $dgKey 'EnableVirtualizationBasedSecurity'            1
        Set-RegValue $dgKey 'RequirePlatformSecurityFeatures'              1  # 1=SecureBoot only; 3=SecureBoot+DMA (rejects on systems w/o IOMMU)
        Set-RegValue $dgKey 'HypervisorEnforcedCodeIntegrity'              1
        Set-RegValue $dgKey 'HVCIMATRequired'                              0
        Set-RegValue $dgKey 'LsaCfgFlags'                                  1  # CG enabled with UEFI lock
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 1
    }

# --- NTLMv1 disable ---
Test-And-Set -ID 'CRED-004' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Set LAN Manager Authentication Level to NTLMv2 only' `
    -Description 'NTLMv1 hashes are trivially crackable; force NTLMv2 with session security' `
    -Reference 'CIS L1 2.3.11.7 | MITRE T1110' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 99
        return $v -ge 5
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 }

# --- No LM hash storage ---
Test-And-Set -ID 'CRED-005' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Do not store LAN Manager hash' `
    -Description 'LM hashes use DES, can be cracked in seconds with modern hardware' `
    -Reference 'CIS L1 2.3.11.3' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1 }

# --- NTLM Extended Session Security ---
Test-And-Set -ID 'CRED-006' -Category 'Credentials' -Severity 'MEDIUM' `
    -Name 'Require 128-bit session security for NTLM' `
    -Description 'Prevents use of weak NTLM session encryption' `
    -Reference 'CIS L1 2.3.11.9' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f && NTLMMinClientSec /d 537395200 /f' `
    -CheckScript {
        $vSrv = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' 0
        $vCli = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 0
        # 0x20000000 = NTLMv2 session security; 0x80000000 = 128-bit encryption
        return ((($vSrv -band 0x20000000) -ne 0) -and (($vSrv -band 0x80000000) -ne 0) -and
                (($vCli -band 0x20000000) -ne 0) -and (($vCli -band 0x80000000) -ne 0))
    } `
    -BackupScript {
        @{
            Srv = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec')
            Cli = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec')
        }
    } `
    -ApplyScript {
        # 0x20000000 = NTLMv2 session security | 0x80000000 = 128-bit encryption
        $flags = 0x20000000 -bor 0x80000000  # = 537395200
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' $flags
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' $flags
    }


# --- SEHOP (Structured Exception Handler Overwrite Protection) ---
Test-And-Set -ID 'CRED-007' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Enable SEHOP (Structured Exception Handler Overwrite Protection)' `
    -Description 'SEHOP validates the exception handler chain before dispatching exceptions, blocking SEH-overwrite exploits. No reboot required; safe on all domain and standalone configs.' `
    -Reference 'MS KB956525 | MITRE T1203' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 99
        return ($v -eq 0) -or ($v -eq 99)  # 0=enabled; absent=default enabled on modern Windows
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0 }

# --- CredSSP Oracle (CVE-2018-0886) ---
Test-And-Set -ID 'CRED-008' -Category 'Credentials' -Severity 'CRITICAL' `
    -Name 'CredSSP: mitigate Oracle attack (CVE-2018-0886)' `
    -Description 'CVE-2018-0886: unauthenticated attacker can relay CredSSP credentials for RCE. Two acceptable safe states: AllowEncryptionOracle=0 (Force Updated Clients, strict -- requires ALL endpoints patched) or =2 (Mitigated, defends against the attack while remaining compatible with unpatched peers). The script auto-detects credssp.dll version and picks the strictest safe value: =0 if the local credssp is patched (May 2018+), =2 otherwise. Compliant = 0 OR 2 (vulnerable value 1 is rejected). Setting =0 unconditionally on a server with unpatched RDP clients on the other end will break remote desktop sessions.' `
    -Reference 'CVE-2018-0886 | MS ADV180005 | KB4093492 | MITRE T1557' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f  (use 0 only if all RDP clients/servers are patched)' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'AllowEncryptionOracle' 99
        # Compliant = either Force Updated (0) or Mitigated (2). 1 (Vulnerable) and 99 (unset) are NOT compliant.
        return ($v -eq 0) -or ($v -eq 2)
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'AllowEncryptionOracle' } `
    -ApplyScript  {
        # Decide between 0 (Force Updated Clients, strict) and 2 (Mitigated, compatible).
        # The decision is based on whether the local credssp.dll is patched.
        # The May 2018 patch shipped these minimum versions per OS:
        #   Win10 1607 / Server 2016 : 10.0.14393.2273
        #   Win10 1703 / 1709        : 10.0.15063.1029 / 10.0.16299.402
        #   Win10 1803               : 10.0.17134.1
        #   Win 7    / Server 2008R2 : 6.1.7601.24117
        #   Win 8.1  / Server 2012R2 : 6.3.9600.18999
        # We use a simple proxy: any FilePrivatePart >= 18999 on 6.x, or >= 2273 on 10.x is patched.
        $dllPath  = Join-Path $env:WinDir 'System32\credssp.dll'
        $patched  = $false
        $verLabel = 'unknown'
        $useValue = 2   # safe default

        try {
            if (Test-Path $dllPath) {
                $vi = (Get-Item $dllPath).VersionInfo
                $verLabel = "$($vi.FileMajorPart).$($vi.FileMinorPart).$($vi.FileBuildPart).$($vi.FilePrivatePart)"
                $major = [int]$vi.FileMajorPart
                $build = [int]$vi.FileBuildPart
                $priv  = [int]$vi.FilePrivatePart

                if ($major -ge 10) {
                    # Win10/Server2016+ family
                    if     ($build -ge 17134) { $patched = $true }                     # 1803+ all patched
                    elseif ($build -eq 16299 -and $priv -ge 402)  { $patched = $true } # 1709
                    elseif ($build -eq 15063 -and $priv -ge 1029) { $patched = $true } # 1703
                    elseif ($build -eq 14393 -and $priv -ge 2273) { $patched = $true } # 1607/Srv2016
                } elseif ($major -eq 6) {
                    # 6.1=Win7/2008R2, 6.2=Win8/2012, 6.3=Win8.1/2012R2
                    if ($priv -ge 18999) { $patched = $true }
                }
            } else {
                Write-Info "  credssp.dll not found at $dllPath -- defaulting to Mitigated (2)"
            }
        } catch {
            Write-Info "  Could not read credssp.dll version ($($_.Exception.Message)) -- defaulting to Mitigated (2)"
        }

        if ($patched) {
            $useValue = 0
            Write-Info "  credssp.dll v$verLabel is patched (post-May-2018) -- applying Force Updated Clients (0)"
        } else {
            $useValue = 2
            Write-Info "  credssp.dll v$verLabel is unpatched or pre-May-2018 -- applying Mitigated (2) to preserve RDP compatibility"
            Write-Info "  Install KB4093492 (or newer cumulative) and re-run to enable Force Updated Clients"
        }

        $kParent = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP'
        $k       = "$kParent\Parameters"
        if (-not (Test-Path $kParent)) { $null = New-Item $kParent -Force }
        if (-not (Test-Path $k))       { $null = New-Item $k       -Force }
        Set-RegValue $k 'AllowEncryptionOracle' $useValue
    }

# --- Kerberos encryption types: AES only, no RC4/DES ---
Test-And-Set -ID 'CRED-009' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Kerberos: require AES encryption (disable RC4/DES)' `
    -Description 'Forces Kerberos to negotiate AES-128/256 only, eliminating RC4 ticket cracking (Kerberoasting / AS-REP roasting). On domain-joined machines, Apply queries every Domain Controller via LDAP and verifies that msDS-SupportedEncryptionTypes on each DC includes AES-128 (0x8) AND AES-256 (0x10). If even one DC does not advertise AES support, the registry key is NOT written -- you would lose authentication. Re-run after raising AES support on all DCs. Value 2147483640 = AES128+AES256+Future types.' `
    -Reference 'CIS L1 | MITRE T1558.003 | MS KB977321' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f  (only after verifying all DCs support AES via Get-ADComputer -Filter "OperatingSystem -like ''*Server*''" -Properties msDS-SupportedEncryptionTypes)' `
    -RebootRequired 'Yes' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 0
        # AES128=0x8, AES256=0x10 -- both required, RC4/DES bits ignored
        return (($v -band 0x00000008) -ne 0) -and (($v -band 0x00000010) -ne 0)
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' } `
    -ApplyScript  {
        # Pre-flight: check whether the host is domain-joined. Standalone hosts can still
        # benefit from setting AES-only (defence in depth), so we only block apply on
        # domain-joined hosts where a misconfiguration could break domain authentication.
        $isDomainJoined = $false
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop
            if ($cs -and $cs.PartOfDomain) { $isDomainJoined = $true }
        } catch {}

        if ($isDomainJoined) {
            # LDAP query every DC's msDS-SupportedEncryptionTypes attribute via [adsisearcher].
            # This works without RSAT (no Get-ADComputer / Get-ADDomainController needed).
            # If even one DC lacks AES bits, refuse to apply.
            $aesOk      = $true
            $dcsChecked = 0
            $dcFailures = New-Object System.Collections.ArrayList

            try {
                $searcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
                # UAC bit 0x2000 (8192) = SERVER_TRUST_ACCOUNT == Domain Controller
                $searcher.PageSize  = 100
                $searcher.PropertiesToLoad.AddRange(@('name','msDS-SupportedEncryptionTypes','dNSHostName')) | Out-Null

                $results = $searcher.FindAll()
                foreach ($r in $results) {
                    $dcsChecked++
                    $name   = $null
                    $encTyp = 0
                    if ($r.Properties['name'].Count -gt 0)         { $name   = [string]$r.Properties['name'][0] }
                    if ($r.Properties['dnshostname'].Count -gt 0)  { $name   = [string]$r.Properties['dnshostname'][0] }
                    if ($r.Properties['msds-supportedencryptiontypes'].Count -gt 0) {
                        $encTyp = [int]$r.Properties['msds-supportedencryptiontypes'][0]
                    }

                    $hasAes128 = (($encTyp -band 0x00000008) -ne 0)
                    $hasAes256 = (($encTyp -band 0x00000010) -ne 0)
                    if (-not ($hasAes128 -and $hasAes256)) {
                        $aesOk = $false
                        $null = $dcFailures.Add("$name (msDS-SupportedEncryptionTypes=0x$($encTyp.ToString('X')))")
                    }
                }
                $results.Dispose()
            } catch {
                # If LDAP query fails entirely, we cannot prove AES support -- refuse to apply.
                throw "SKIP: cannot verify DC AES support via LDAP ($($_.Exception.Message)). Re-run from a host that can query AD, or disable this control via -SkipCredentialProtection."
            }

            if ($dcsChecked -eq 0) {
                throw "SKIP: no Domain Controllers found via LDAP -- cannot verify AES support. Re-run on a host with domain connectivity."
            }

            if (-not $aesOk) {
                $listText = $dcFailures -join '; '
                throw "AES encryption is NOT enabled on the following DC(s): $listText. Refusing to apply CRED-009 -- this would break Kerberos. Raise msDS-SupportedEncryptionTypes on those DCs (set bits 0x18) and re-run."
            }

            Write-Info "  Verified AES support on $dcsChecked Domain Controller(s); proceeding"
        } else {
            Write-Info "  Standalone host -- applying AES-only without DC verification"
        }

        $kRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos'
        $k     = "$kRoot\Parameters"
        if (-not (Test-Path $kRoot)) { $null = New-Item $kRoot -Force }
        if (-not (Test-Path $k))     { $null = New-Item $k     -Force }
        Set-RegValue $k 'SupportedEncryptionTypes' 2147483640
    }

# --- Remote Credential Guard for RDP ---
Test-And-Set -ID 'CRED-010' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Enable Remote Credential Guard / Restricted Admin for RDP' `
    -Description 'AllowProtectedCreds=1 prevents credential forwarding during RDP sessions (Remote Credential Guard). Credentials stay on the local machine, not the remote host. Requirements: domain-joined host AND Win10 1607 / Server 2016+ (build 14393+) on BOTH endpoints. Standalone hosts and older Windows versions are not supported -- script will report N/A on those. On supported hosts the setting is safe to apply.' `
    -Reference 'MS Remote Credential Guard | MITRE T1021.001' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f' `
    -CheckScript {
        # First check supported-OS / domain gate. If not eligible, mark N/A.
        $isDomainJoined = $false
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop
            if ($cs -and $cs.PartOfDomain) { $isDomainJoined = $true }
        } catch {}

        $build = [int][Environment]::OSVersion.Version.Build

        if (-not $isDomainJoined) {
            throw "SKIP: host is not domain-joined (Remote Credential Guard requires AD)"
        }
        if ($build -lt 14393) {
            throw "SKIP: OS build $build is below 14393 (Win10 1607 / Server 2016 minimum)"
        }

        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' } `
    -ApplyScript  {
        # Re-validate gates inside Apply too -- defence in depth.
        $isDomainJoined = $false
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop
            if ($cs -and $cs.PartOfDomain) { $isDomainJoined = $true }
        } catch {}
        $build = [int][Environment]::OSVersion.Version.Build

        if (-not $isDomainJoined) { throw "SKIP: host is not domain-joined" }
        if ($build -lt 14393)     { throw "SKIP: OS build $build < 14393" }

        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'AllowProtectedCreds' 1
    }

# --- Netlogon secure channel (domain hardening) ---
Test-And-Set -ID 'CRED-011' -Category 'Credentials' -Severity 'HIGH' `
    -Name 'Netlogon: require signed/sealed secure channel and strong session key' `
    -Description 'Requires signing and encryption of Netlogon secure channel between workstation and DC. Prevents Netlogon MITM attacks (ZeroLogon-era hardening). Fully safe on domain with Server 2008+ DCs. On standalone the keys are written but have no operational effect.' `
    -Reference 'CIS L1 2.3.6.x | CVE-2020-1472 | MITRE T1557' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f  (also: SealSecureChannel, SignSecureChannel, RequireStrongKey=1; DisablePasswordChange=0)' `
    -CheckScript {
        $p    = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        $rsos = Get-RegValue $p 'RequireSignOrSeal'    0
        $seal = Get-RegValue $p 'SealSecureChannel'    0
        $sign = Get-RegValue $p 'SignSecureChannel'    0
        $strk = Get-RegValue $p 'RequireStrongKey'     0
        $nopc = Get-RegValue $p 'DisablePasswordChange' 99
        return ($rsos -eq 1) -and ($seal -eq 1) -and ($sign -eq 1) -and ($strk -eq 1) -and ($nopc -eq 0)
    } `
    -BackupScript {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        @{
            RequireSignOrSeal    = (Backup-RegValue $p 'RequireSignOrSeal')
            SealSecureChannel    = (Backup-RegValue $p 'SealSecureChannel')
            SignSecureChannel    = (Backup-RegValue $p 'SignSecureChannel')
            RequireStrongKey     = (Backup-RegValue $p 'RequireStrongKey')
            DisablePasswordChange= (Backup-RegValue $p 'DisablePasswordChange')
        }
    } `
    -ApplyScript {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        Set-RegValue $p 'RequireSignOrSeal'     1
        Set-RegValue $p 'SealSecureChannel'     1
        Set-RegValue $p 'SignSecureChannel'     1
        Set-RegValue $p 'RequireStrongKey'      1
        Set-RegValue $p 'DisablePasswordChange' 0  # allow machine account password rotation
    }

} # end SkipCredentialProtection

# ===========================================================
# SECTION 3: POWERSHELL HARDENING
# ===========================================================
if (-not $SkipPowerShell) {

Write-Phase "POWERSHELL HARDENING"

# --- Script Block Logging ---
Test-And-Set -ID 'PS-001' -Category 'PowerShell' -Severity 'HIGH' `
    -Name 'Enable PowerShell Script Block Logging (Event 4104)' `
    -Description 'Script Block Logging records all PS code executed, including decoded obfuscated commands' `
    -Reference 'MITRE T1059.001 | CIS L1' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' } `
    -ApplyScript  {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'EnableScriptBlockLogging'         1
        Set-RegValue $k 'EnableScriptBlockInvocationLogging' 1
    }

# --- Module Logging ---
Test-And-Set -ID 'PS-002' -Category 'PowerShell' -Severity 'HIGH' `
    -Name 'Enable PowerShell Module Logging (Event 4103)' `
    -Description 'Module logging records pipeline execution details for all modules' `
    -Reference 'MITRE T1059.001 | CIS L1' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f  + add ModuleNames\* = *' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' } `
    -ApplyScript  {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'EnableModuleLogging' 1
        # Log all modules
        $mk = "$k\ModuleNames"
        if (-not (Test-Path $mk)) { $null = New-Item $mk -Force }
        Set-ItemProperty -Path $mk -Name '*' -Value '*' -Type String -Force
    }

# --- Transcription ---
Test-And-Set -ID 'PS-003' -Category 'PowerShell' -Severity 'MEDIUM' `
    -Name 'Enable PowerShell Transcription' `
    -Description 'Transcription saves full console input/output to text files for forensic review' `
    -Reference 'MITRE T1059.001' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f  + set OutputDirectory value' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' } `
    -ApplyScript  {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'EnableTranscripting'     1
        Set-RegValue $k 'EnableInvocationHeader'  1
        $transcriptDir = 'C:\ProgramData\PSTranscripts'
        if (-not (Test-Path $transcriptDir)) { $null = New-Item $transcriptDir -ItemType Directory -Force }
        Set-RegValue $k 'OutputDirectory' $transcriptDir -Type String
    }

# --- PowerShell v2 ---
Test-And-Set -ID 'PS-004' -Category 'PowerShell' -Severity 'HIGH' `
    -Name 'Disable PowerShell v2 engine' `
    -Description 'PS v2 bypasses Script Block Logging; used for AMSI bypass via powershell -version 2' `
    -Reference 'MITRE T1059.001' `
    -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2,MicrosoftWindowsPowerShellV2Root -NoRestart  (requires reboot)' `
    -CheckScript {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -EA SilentlyContinue
        if ($feature) {
            # 'Disabled' = applied; 'DisablePending' = applied but pending reboot
            return $feature.State -in @('Disabled','DisablePending')
        }
        # Feature not present at all (modern Server SKU may lack it) -- treat as compliant
        return $true
    } `
    -BackupScript {
        $f1 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2'     -EA SilentlyContinue
        $f2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -EA SilentlyContinue
        return @{
            PSv2State     = if ($f1) { $f1.State.ToString() } else { 'NotPresent' }
            PSv2RootState = if ($f2) { $f2.State.ToString() } else { 'NotPresent' }
        }
    } `
    -ApplyScript  {
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart -EA SilentlyContinue
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -EA SilentlyContinue
    } -RebootRequired 'Yes'

# --- Execution Policy ---
Test-And-Set -ID 'PS-005' -Category 'PowerShell' -Severity 'MEDIUM' `
    -Name 'Set PowerShell Execution Policy to RemoteSigned (Machine)' `
    -Description 'Prevents execution of unsigned remote scripts; local scripts still run' `
    -Reference 'CIS L1' `
    -Remediation 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force  OR GPO: Computer Config > Admin Templates > Windows Components > PowerShell' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' ''
        return $v -in @('RemoteSigned','AllSigned','Restricted')
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' } `
    -ApplyScript  {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'EnableScripts'    1
        Set-RegValue $k 'ExecutionPolicy'  'RemoteSigned' -Type String
    }

} # end SkipPowerShell

# ===========================================================
# SECTION 4: AUDIT POLICY
# ===========================================================
if (-not $SkipAuditPolicy) {

Write-Phase "AUDIT POLICY"

function Set-AuditSubcat {
    param([string]$Guid, [string]$SubcatName, [string]$Setting)
    $sFlag = if ($Setting -match 'Success') { 'enable' } else { 'disable' }
    $fFlag = if ($Setting -match 'Failure') { 'enable' } else { 'disable' }
    $ap = "$env:SystemRoot\System32\auditpol.exe"
    $result = & $ap /set /subcategory:"$Guid" /success:$sFlag /failure:$fFlag 2>&1
    if ($LASTEXITCODE -ne 0) {
        $msg = ($result | Out-String).Trim()
        Write-Err "  auditpol failed for '$SubcatName': $msg"
        return $false
    }
    return $true
}

function Get-AuditSubcat {
    param([string]$Guid)
    # Reads audit subcategory state via auditpol /r CSV mode.
    # CRITICAL: This function is READ-ONLY. It MUST NOT modify system state, because it
    # is called from CheckScript which runs in Audit mode (where no changes are allowed).
    #
    # auditpol /r CSV columns (zero-indexed):
    #   [0] Computer Name / Machine
    #   [1] Policy Target
    #   [2] Subcategory (localized)
    #   [3] Subcategory GUID
    #   [4] Inclusion Setting (localized: "No Auditing" / "Success" / "Failure" / "Success and Failure")
    #
    # Strategy: parse column 4 by recognizing localized keywords for Success and Failure.
    # We support multiple locales (English, Russian, German, French, Spanish, Italian, Polish, Turkish, etc.).
    # If the locale is unknown, we fall back to "presence of space" heuristic: a 2-word
    # value is treated as "Success and Failure"; an empty value is "No Auditing".

    $ap = "$env:SystemRoot\System32\auditpol.exe"
    $out = & $ap /get /subcategory:"$Guid" /r 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $out -or $out.Count -lt 3) { return 'Not Configured' }

    # Find the data line: first line that contains the GUID
    $dataLine = $null
    foreach ($line in $out) {
        $s = [string]$line
        if ($s -match [regex]::Escape($Guid)) { $dataLine = $s; break }
    }
    if (-not $dataLine) { return 'Not Configured' }

    $cols = $dataLine -split ','
    if ($cols.Count -lt 5) { return 'Not Configured' }
    $col4 = $cols[4].Trim()

    if ([string]::IsNullOrWhiteSpace($col4)) { return 'No Auditing' }

    # Locale-aware keyword matching (case-insensitive). Add languages as needed.
    # The token list deliberately covers stems so that case/inflection differences match.
    # Non-ASCII tokens are written as Unicode regex escapes (\uXXXX) so this file stays
    # pure ASCII -- this avoids encoding pitfalls on Windows PowerShell 5.1, which reads
    # .ps1 files as the active ANSI codepage when no BOM is present.
    #
    # Russian:    \u0423\u0441\u043f\u0435\u0445 = "Uspekh"  (Success);
    #             \u0421\u0431\u043e\u0439      = "Sboy"    (Failure);
    #             \u041e\u0442\u043a\u0430\u0437 = "Otkaz"  (Failure)
    # German:     Erfolg / Fehler
    # French:     Reussite / Echec
    # Spanish:    Exito / Fracaso        (also Portuguese: Sucesso / Falha)
    # Italian:    Successo / Errore
    # Polish:     Powodzenie / Niepowodzenie
    # Turkish:    Basari / Basarisiz
    # Chinese:    \u6210\u529f / \u5931\u8d25
    # Japanese:   \u6210\u529f / \u5931\u6557
    $successWords = @(
        'success',
        'usp', '\u0443\u0441\u043f',
        'erfolg',
        'reuss',
        'succes', 'sucesso',
        '\u00e9xito',
        'successo',
        'powodz',
        'basari',
        '\u6210\u529f'
    )
    $failureWords = @(
        'failure', 'fail',
        'sboi', '\u0441\u0431\u043e', '\u043e\u0442\u043a\u0430\u0437',
        'fehler',
        'echec', '\u00e9chec',
        'fracaso', 'falha',
        'errore',
        'niepowodz',
        'basarisiz',
        '\u5931\u8d25', '\u5931\u6557'
    )

    $low = $col4.ToLowerInvariant()
    $hasSuccess = $false
    $hasFailure = $false
    foreach ($w in $successWords) { if ($low -match $w) { $hasSuccess = $true; break } }
    foreach ($w in $failureWords) { if ($low -match $w) { $hasFailure = $true; break } }

    if ($hasSuccess -and $hasFailure) { return 'Success,Failure' }
    if ($hasSuccess)                  { return 'Success' }
    if ($hasFailure)                  { return 'Failure' }

    # Fallback heuristic for unknown locales: if value contains a space/conjunction,
    # treat as "both"; otherwise mark as Configured-Unknown so the caller can flag it.
    if ($col4 -match '[\s,/&+]') { return 'Success,Failure' }
    return 'Configured-Unknown'
}

$auditChecks = @(
    @{ ID='AUD-001'; Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Sub='Process Creation';                Want='Success,Failure'; Sev='HIGH';     Desc='4688: Process creation' }
    @{ ID='AUD-002'; Guid='{0CCE9223-69AE-11D9-BED3-505054503030}'; Sub='Process Termination';             Want='Success';         Sev='LOW';      Desc='4689: Process termination' }
    @{ ID='AUD-003'; Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Sub='Logon';                          Want='Success,Failure'; Sev='CRITICAL'; Desc='4624/4625: Logon success/failure' }
    @{ ID='AUD-004'; Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Sub='Logoff';                         Want='Success';         Sev='LOW';      Desc='4634/4647: Logoff events' }
    @{ ID='AUD-005'; Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Sub='Account Lockout';                Want='Failure';         Sev='HIGH';     Desc='4740: Account lockout' }
    @{ ID='AUD-006'; Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Sub='Special Logon';                  Want='Success';         Sev='HIGH';     Desc='4672: Admin logon' }
    @{ ID='AUD-007'; Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Authentication Service'; Want='Success,Failure'; Sev='HIGH';    Desc='4768/4771: Kerberos auth' }
    @{ ID='AUD-008'; Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Service Ticket Ops';    Want='Success,Failure'; Sev='HIGH';     Desc='4769: Kerberoasting' }
    @{ ID='AUD-009'; Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Sub='Credential Validation';          Want='Success,Failure'; Sev='HIGH';     Desc='4776: NTLM validation' }
    @{ ID='AUD-010'; Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Sub='User Account Management';        Want='Success,Failure'; Sev='HIGH';     Desc='4720-4726: Account changes' }
    @{ ID='AUD-011'; Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Sub='Security Group Management';      Want='Success';         Sev='HIGH';     Desc='4732/4728/4756: Group changes' }
    @{ ID='AUD-012'; Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Sub='Audit Policy Change';            Want='Success,Failure'; Sev='CRITICAL'; Desc='4719: Audit policy change' }
    @{ ID='AUD-013'; Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Sub='Authentication Policy Change';   Want='Success';         Sev='HIGH';     Desc='4706/4713: Trust/Kerberos changes' }
    @{ ID='AUD-014'; Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Sub='System Integrity';               Want='Success,Failure'; Sev='CRITICAL'; Desc='4612/4615: Integrity violations' }
    @{ ID='AUD-015'; Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Sub='Security System Extension';      Want='Success';         Sev='HIGH';     Desc='4610/4614: Auth package loading' }
    @{ ID='AUD-016'; Guid='{0CCE921D-69AE-11D9-BED3-505054503030}'; Sub='File System';                    Want='Success,Failure'; Sev='MEDIUM';   Desc='4663: File access audit' }
    @{ ID='AUD-017'; Guid='{0CCE921E-69AE-11D9-BED3-505054503030}'; Sub='Registry';                       Want='Success,Failure'; Sev='MEDIUM';   Desc='4657: Registry modification' }
    @{ ID='AUD-018'; Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Sub='Sensitive Privilege Use';        Want='Success,Failure'; Sev='HIGH';     Desc='4673/4674: Privilege use' }
    @{ ID='AUD-019'; Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Sub='Other Object Access Events';     Want='Success,Failure'; Sev='MEDIUM';   Desc='4698/4702: Scheduled tasks' }
    @{ ID='AUD-020'; Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Sub='Removable Storage';              Want='Success,Failure'; Sev='MEDIUM';   Desc='4656/4663: USB access' }
    @{ ID='AUD-021'; Guid='{0CCE922D-69AE-11D9-BED3-505054503030}'; Sub='DPAPI Activity';                 Want='Success,Failure'; Sev='MEDIUM';   Desc='4692/4693: DPAPI activity' }
    @{ ID='AUD-022'; Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Sub='RPC Events';                     Want='Success,Failure'; Sev='LOW';      Desc='5712: RPC calls' }
    @{ ID='AUD-023'; Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Sub='Security State Change';          Want='Success';         Sev='HIGH';     Desc='4608/4609: Startup/shutdown' }
    @{ ID='AUD-024'; Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; Sub='Other System Events';            Want='Success,Failure'; Sev='MEDIUM';   Desc='5024/5025: Firewall events' }
    @{ ID='AUD-025'; Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Sub='Filtering Platform Connection';  Want='Failure';         Sev='LOW';      Desc='5157: Blocked connections' }
    @{ ID='AUD-026'; Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; Sub='Detailed File Share';            Want='Failure';         Sev='MEDIUM';   Desc='5145: Share access violations' }
    @{ ID='AUD-027'; Guid='{0CCE9243-69AE-11D9-BED3-505054503030}'; Sub='Network Policy Server';          Want='Success,Failure'; Sev='LOW';      Desc='6272/6273: NPS auth events' }
)

foreach ($ac in $auditChecks) {
    $acID   = $ac.ID
    $acGuid = $ac.Guid
    $acSub  = $ac.Sub
    $acWant = $ac.Want
    $acSev  = $ac.Sev
    $acDesc = $ac.Desc

    Test-And-Set -ID $acID -Category 'AuditPolicy' -Severity $acSev `
        -Name "Audit: $acSub ($acWant)" `
        -Description $acDesc `
        -Remediation "auditpol /set /subcategory:`"$acGuid`"" `
        -Reference "GUID $acGuid" `
        -CheckScript ([scriptblock]::Create("
            `$current = Get-AuditSubcat '$acGuid'
            `$want    = '$acWant'
            # 'Configured-Unknown' = locale-unrecognized but auditing enabled with both flags
            if (`$want -eq 'Success,Failure') { return `$current -in @('Success,Failure','Configured-Unknown') }
            if (`$want -eq 'Success')         { return `$current -in @('Success','Success,Failure','Configured-Unknown') }
            if (`$want -eq 'Failure')         { return `$current -in @('Failure','Success,Failure','Configured-Unknown') }
            return `$false
        ")) `
        -BackupScript ([scriptblock]::Create("
            return @{ Subcategory = '$acSub'; Guid = '$acGuid'; Setting = (Get-AuditSubcat '$acGuid') }
        ")) `
        -ApplyScript ([scriptblock]::Create("
            Set-AuditSubcat '$acGuid' '$acSub' '$acWant'
            Start-Sleep -Milliseconds 200
        "))
}

# SCENoApplyLegacyAuditPolicy - if 0, legacy GPO overrides auditpol subcategory settings
Test-And-Set -ID 'AUD-029' -Category 'AuditPolicy' -Severity 'CRITICAL' `
    -Name 'Enable Advanced Audit Policy override (SCENoApplyLegacyAuditPolicy)' `
    -Description 'If 0 or missing, legacy Audit Policy from GPO overrides advanced audit settings. Fix this first.' `
    -Reference 'MS KB921468 | CIS L1' `
    -Remediation 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 0
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 }

# Command line in 4688
Test-And-Set -ID 'AUD-028' -Category 'AuditPolicy' -Severity 'CRITICAL' `
    -Name 'Include command line in Process Creation events (4688)' `
    -Description 'Without this, Event 4688 logs the process image name but NOT its arguments. LOLBins (certutil, mshta, wscript, rundll32, powershell -enc) become invisible to SIEM. Zero performance impact, no domain compatibility risk.' `
    -Reference 'MS KB3004375 | CIS L1 | MITRE T1059' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' } `
    -ApplyScript  {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        if (-not (Test-Path $k)) { $null = New-Item $k -Force }
        Set-RegValue $k 'ProcessCreationIncludeCmdLine_Enabled' 1
    }

} # end SkipAuditPolicy

# ===========================================================
# SECTION 5: SYSTEM HARDENING
# ===========================================================
Write-Phase "SYSTEM HARDENING"

# --- UAC ---
Test-And-Set -ID 'SYS-001' -Category 'System' -Severity 'HIGH' `
    -Name 'Enable UAC (full enforcement)' `
    -Description 'UAC must be enabled and configured to prompt even for built-in admins' `
    -Reference 'CIS L1 | MITRE T1548.002' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f && /v ConsentPromptBehaviorAdmin /d 2 /f' `
    -CheckScript {
        $enabled = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 99
        $behavior= Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 99
        return ($enabled -eq 1) -and ($behavior -ge 2)
    } `
    -BackupScript {
        @{
            EnableLUA    = (Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
            AdminBehavior= (Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
        }
    } `
    -ApplyScript {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-RegValue $k 'EnableLUA'                    1
        Set-RegValue $k 'ConsentPromptBehaviorAdmin'   2  # Prompt for consent on secure desktop
        Set-RegValue $k 'ConsentPromptBehaviorUser'    0  # Automatically deny elevation requests
        Set-RegValue $k 'PromptOnSecureDesktop'        1
    }

# --- AutoRun / AutoPlay ---
Test-And-Set -ID 'SYS-002' -Category 'System' -Severity 'HIGH' `
    -Name 'Disable AutoRun and AutoPlay' `
    -Description 'AutoRun enables automatic code execution from removable media (USB attacks)' `
    -Reference 'CIS L1 18.9.8 | MITRE T1091' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f' `
    -CheckScript {
        $v1 = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 99
        $v2 = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 99
        return ($v1 -eq 255) -and ($v2 -eq 1)
    } `
    -BackupScript {
        @{
            NoDriveTypeAutoRun   = (Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun')
            NoAutoplayNonVolume  = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume')
        }
    } `
    -ApplyScript {
        $k1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if (-not (Test-Path $k1)) { $null = New-Item $k1 -Force }
        Set-RegValue $k1 'NoDriveTypeAutoRun' 255
        Set-RegValue $k1 'NoAutorun'          1
        $k2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        if (-not (Test-Path $k2)) { $null = New-Item $k2 -Force }
        Set-RegValue $k2 'NoAutoplayfornonVolume' 1
        Set-RegValue $k2 'NoAutorun'              1
    }

# --- Windows Firewall ---
Test-And-Set -ID 'SYS-003' -Category 'System' -Severity 'CRITICAL' `
    -Name 'Enable Windows Firewall (all profiles)' `
    -Description 'Windows Firewall must be enabled on Domain, Private, and Public profiles' `
    -Reference 'CIS L1 9.1.1 | MITRE T1562.004' `
    -Remediation 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True  OR: netsh advfirewall set allprofiles state on' `
    -CheckScript {
        $profiles = Get-NetFirewallProfile -EA SilentlyContinue
        if (-not $profiles) { return $false }
        $profileList = @($profiles)
        if ($profileList.Count -eq 0) { return $false }
        $disabled = @($profileList | Where-Object { $_.Enabled -eq $false })
        return $disabled.Count -eq 0
    } `
    -BackupScript {
        $p = Get-NetFirewallProfile -EA SilentlyContinue
        if ($p) { return @($p | Select-Object Name,Enabled) }
        return @()
    } `
    -ApplyScript {
        # Try via cmdlet first, fall back to netsh (works even when third-party firewall is active)
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -EA SilentlyContinue
        & netsh advfirewall set allprofiles state on 2>&1 | Out-Null
    }

# --- RDP NLA ---
Test-And-Set -ID 'SYS-004' -Category 'System' -Severity 'HIGH' `
    -Name 'Require NLA for Remote Desktop' `
    -Description 'NLA forces authentication before RDP session is established, blocking pre-auth exploits' `
    -Reference 'CIS L1 | MITRE T1021.001' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthenticationRequired /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthenticationRequired' 99
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthenticationRequired' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthenticationRequired' 1 }

# --- DEP ---
Test-And-Set -ID 'SYS-005' -Category 'System' -Severity 'HIGH' `
    -Name 'Enable Data Execution Prevention (DEP) for all programs' `
    -Description 'DEP prevents code execution from non-executable memory regions (shellcode mitigation)' `
    -Reference 'CIS L1' `
    -Remediation 'bcdedit /set "{current}" nx AlwaysOn  (reboot required)' `
    -RebootRequired 'Yes' `
    -CheckScript {
        $bcd = & bcdedit /enum '{current}' 2>&1
        if (-not $bcd) { return $false }
        $dep = $bcd | Where-Object { $_ -match '^\s*nx\s' }
        if (-not $dep) { return $false }
        return ([string]$dep) -match 'AlwaysOn'
    } `
    -BackupScript { return @{ DEP = 'OptIn' } } `
    -ApplyScript  { & bcdedit /set '{current}' nx AlwaysOn 2>&1 | Out-Null }

# --- Event Log Sizes + Retention (profile-aware) ---
# On WORKSTATIONS we use overwrite-when-full (Retention=0) to prevent disk fill-up.
# On SERVERS (DC/FileServer/Exchange/SQL/RDS/PrintServer) we use Archive-when-full
# (Retention=1, AutoBackupLogFiles=1) so log-spam attacks cannot purge older events
# before the SIEM ingests them. Disk is rarely a concern on a server with proper sizing.
$_isServerRole = $DeviceProfile -in @('DomainController','FileServer','Exchange','SQL','RDS','PrintServer')
$_logRetention = if ($_isServerRole) { 1 } else { 0 }   # 0=overwrite, 1=archive
$_logAutoBack  = if ($_isServerRole) { 1 } else { 0 }   # 1=auto-archive, 0=disabled
$_logModeLabel = if ($_isServerRole) { 'archive (server)' } else { 'overwrite (workstation)' }

# Pre-compute strings for wevtutil so the [scriptblock]::Create body is simple text.
$_rtFlag = if ($_logRetention -eq 1) { 'true' } else { 'false' }
$_abFlag = if ($_logAutoBack  -eq 1) { 'true' } else { 'false' }
# In Audit mode (or Custom profile) tolerate both retention schemes -- the operator
# has not declared a role yet, and either choice is defensible.
$_logTolerantStr = if ($isAudit -or ($DeviceProfile -eq 'Custom')) { '$true' } else { '$false' }

Test-And-Set -ID 'SYS-006' -Category 'System' -Severity 'HIGH' `
    -Name "Event Log sizes: Security 1GB, System/App 256MB; retention=$_logModeLabel" `
    -Description "Default log sizes are too small. On servers (DC/FS/Exchange/SQL/RDS/Print) retention is set to ARCHIVE so log-spam attacks cannot evict older events; on workstations retention is set to OVERWRITE to prevent disk fill-up. Current target: $_logModeLabel" `
    -Reference 'CIS L1' `
    -Remediation "wevtutil sl Security /ms:1073741824 /rt:$_rtFlag /ab:$_abFlag" `
    -CheckScript ([scriptblock]::Create("
        `$secSize   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize' 0
        `$retention = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'Retention' 99
        `$autoBack  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'AutoBackupLogFiles' 99
        if (`$secSize -lt 1073741824) { return `$false }
        if ($_logTolerantStr) {
            # Audit/Custom: any reasonable retention scheme is OK
            return (`$retention -in @(0,1)) -and (`$autoBack -in @(0,1,99))
        }
        return (`$retention -eq $_logRetention) -and (`$autoBack -eq $_logAutoBack)
    ")) `
    -BackupScript {
        @{
            Sec    = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'MaxSize')
            Sys    = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'MaxSize')
            App    = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'MaxSize')
            SecRet = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'Retention')
            SysRet = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'Retention')
            AppRet = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'Retention')
            SecAB  = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'AutoBackupLogFiles')
        }
    } `
    -ApplyScript ([scriptblock]::Create("
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'MaxSize' 1073741824
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'MaxSize' 268435456
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'MaxSize' 268435456
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'Retention' $_logRetention
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'Retention' $_logRetention
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'Retention' $_logRetention
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'AutoBackupLogFiles' $_logAutoBack
        & wevtutil sl Security    /ms:1073741824 /rt:$_rtFlag /ab:$_abFlag 2>&1 | Out-Null
        & wevtutil sl System      /ms:268435456  /rt:$_rtFlag /ab:$_abFlag 2>&1 | Out-Null
        & wevtutil sl Application /ms:268435456  /rt:$_rtFlag /ab:$_abFlag 2>&1 | Out-Null
    "))

# --- Secure DNS over HTTPS ---
# DoH is opportunistic on Windows: setting DoHPolicy=2 (Allow) only takes effect if the
# resolver IP is in the system DoH template list (Get-DnsClientDohServerAddress) OR if
# the DNS server is a known Microsoft auto-DoH peer (Cloudflare, Google, Quad9 by IP).
# In a typical AD environment with a local Windows DNS server, DoHPolicy=2 is a no-op.
# Severity is LOW because the setting is harmless but rarely effective unless paired
# with an explicit DohResolvers configuration. Severity is informative only -- the goal
# of this check is to remind the operator that DoH exists, not to flag systems as broken.
Test-And-Set -ID 'SYS-007' -Category 'System' -Severity 'LOW' `
    -Name 'Configure Encrypted DNS (DoH) policy' `
    -Description 'DoH (DNS-over-HTTPS) prevents in-network DNS sniffing and C2-over-DNS. Note: setting DoHPolicy=2 (Allow) is opportunistic -- it only activates if the configured DNS server is recognized as DoH-capable. For real protection, also configure DoH templates per-resolver via Add-DnsClientDohServerAddress, or use DoHPolicy=3 (Require) only after verifying every DNS server has a DoH endpoint. On AD-joined machines using on-prem DNS, this setting is typically a no-op.' `
    -Reference 'MITRE T1071.004 | MS Win10 1903+' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DoHPolicy /t REG_DWORD /d 2 /f  (2=Allow if DoH endpoint known, 3=Require)' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 99
        # 2 = Allow (opportunistic), 3 = Require, 99 = not configured
        return $v -ge 2
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' } `
    -ApplyScript  {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 2
        # Diagnostic hint -- list any DoH server addresses already configured in the system.
        try {
            $doh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue 2>$null
            if (-not $doh -or $doh.Count -eq 0) {
                Write-Info "  DoH policy set to Allow (2) but no DoH server addresses are configured -- effective on auto-DoH peers only"
            } else {
                Write-Info "  DoH policy set; $($doh.Count) DoH server template(s) already configured"
            }
        } catch {}
    }

# --- Disable Print Spooler (optional) ---
if ($EnablePrintSpoolerDisable) {
    Test-And-Set -ID 'SYS-008' -Category 'System' -Severity 'HIGH' `
        -Name 'Disable Print Spooler (PrintNightmare mitigation)' `
        -Description 'Print Spooler (CVE-2021-34527) allows SYSTEM code execution; disable if no printing needed' `
        -Reference 'CVE-2021-34527 | MITRE T1547.010' `
    -Remediation 'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled' `
        -CheckScript {
            $svc = Get-Service 'Spooler' -EA SilentlyContinue
            if (-not $svc) { return $true }  # absent = compliant
            return ($svc.StartType -eq 'Disabled') -and ($svc.Status -eq 'Stopped')
        } `
        -BackupScript {
            $svc = Get-Service 'Spooler' -EA SilentlyContinue
            if (-not $svc) { return @{ StartType = 'Absent' } }
            return @{ StartType = $svc.StartType.ToString() }
        } `
        -ApplyScript {
            $svc = Get-Service 'Spooler' -EA SilentlyContinue
            if (-not $svc) { return }
            Stop-Service 'Spooler' -Force -EA SilentlyContinue
            Set-Service  'Spooler' -StartupType Disabled -EA SilentlyContinue
        }
}

# --- Disable LLMNR Service ---
Test-And-Set -ID 'SYS-009' -Category 'System' -Severity 'MEDIUM' `
    -Name 'Disable DNS Client service multicast (DNS Client dnscache)' `
    -Description 'Supplementary: disable multicast via service restriction' `
    -Reference 'CIS L1' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 99
        return $v -eq 0
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }

# --- Disable weak RDP encryption ---
Test-And-Set -ID 'SYS-010' -Category 'System' -Severity 'HIGH' `
    -Name 'Set RDP encryption level to High (FIPS)' `
    -Description 'Weak RDP encryption allows session hijacking and credential theft' `
    -Reference 'CIS L1' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 3 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' 99
        return $v -ge 3  # 3=High, 4=FIPS
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' 3 }

# NOTE: Former SYS-011 (Process Creation cmdline) is now AUD-028 -- single source of truth.
# NOTE: Former SYS-012 (SCENoApplyLegacyAuditPolicy) is now AUD-029 -- single source of truth.
# Both moved to AuditPolicy section; if -SkipAuditPolicy is used, run AUD-028/029 manually.

# --- Authenticode certificate padding check (Flame malware mitigation) ---
Test-And-Set -ID 'SYS-013' -Category 'System' -Severity 'HIGH' `
    -Name 'Enable Authenticode certificate padding check (Flame mitigation)' `
    -Description 'The Flame malware (2012) forged valid Microsoft certificates by exploiting a collision in MD5 Authenticode padding. EnableCertPaddingCheck=1 adds extra validation during signature verification. Zero performance impact; safe on all configurations.' `
    -Reference 'MS KB2661254 | MITRE T1553.002' `
    -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck' 0
        return $v -eq 1
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck' } `
    -ApplyScript  {
        $kRoot = 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust'
        $k     = "$kRoot\Config"
        if (-not (Test-Path $kRoot)) { $null = New-Item $kRoot -Force }
        if (-not (Test-Path $k))     { $null = New-Item $k     -Force }
        Set-RegValue $k 'EnableCertPaddingCheck' 1
    }

# --- NTLM Audit (incoming traffic) ---
Test-And-Set -ID 'SYS-014' -Category 'System' -Severity 'MEDIUM' `
    -Name 'Enable NTLM incoming traffic audit' `
    -Description 'AuditReceivingNTLMTraffic=2 logs all incoming NTLM authentication attempts to the Security event log (Event 8004). Allows SIEM to identify legacy NTLM usage and machines still relying on NTLMv1/v2. Read-only audit -- zero operational impact.' `
    -Reference 'CIS | MITRE T1557.001' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0" /v AuditReceivingNTLMTraffic /t REG_DWORD /d 2 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' 0
        return $v -eq 2
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' 2 }

# --- Null session LocalSystem fallback ---
Test-And-Set -ID 'SYS-015' -Category 'System' -Severity 'MEDIUM' `
    -Name 'Disable NULL session fallback for LocalSystem (MSV1_0)' `
    -Description 'Prevents LocalSystem from falling back to an anonymous NULL session for NTLM authentication. Safe on all domain and standalone configurations; does not affect normal service account behaviour.' `
    -Reference 'CIS L1 2.3.10.x' `
    -Remediation 'reg add "HKLM\SYSTEM\CCS\Control\Lsa\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback' 99
        return $v -eq 0
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback' 0 }

# ===========================================================
# SECTION 6: SAVE BACKUP & GENERATE REPORT
# ===========================================================
Write-Phase "Saving backup and generating report"

if ($isApply) {
    # Save backup - use -ErrorAction Stop explicitly to override global SilentlyContinue
    $backupSaved = $false
    try {
        $backupDir = Split-Path $BackupPath -Parent
        if ($backupDir -and -not (Test-Path $backupDir)) {
            $null = New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop
        }
        if ($global:Backup.Count -gt 0) {
            $jsonText = $global:Backup | ConvertTo-Json -Depth 10
        } else {
            $jsonText = [ordered]@{
                _meta = 'No changes applied - all settings were already compliant'
                _host = $env:COMPUTERNAME
                _time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            } | ConvertTo-Json
        }
        [System.IO.File]::WriteAllText($BackupPath, $jsonText, [System.Text.Encoding]::UTF8)
        $backupSaved = Test-Path $BackupPath
    } catch {
        Write-Err "Backup save failed: $($_.Exception.Message)"
    }

    if ($backupSaved) {
        Write-Pass "Backup saved: $BackupPath ($($global:Backup.Count) entries)"
    } else {
        # Last resort - try writing to TEMP
        $fallbackPath = "$env:TEMP\HardeningBackup_$env:COMPUTERNAME.json"
        try {
            if ($global:Backup.Count -gt 0) {
                $jsonText = $global:Backup | ConvertTo-Json -Depth 10
            } else {
                $jsonText = '{ "_meta": "all compliant" }'
            }
            [System.IO.File]::WriteAllText($fallbackPath, $jsonText, [System.Text.Encoding]::UTF8)
            Write-Fail "Could not write to original path. Backup saved to fallback: $fallbackPath"
        } catch {
            Write-Err "BACKUP NOT SAVED. Manual rollback may be required."
            Write-Err "Error: $($_.Exception.Message)"
        }
    }
}

$compliantCount    = [int]@($global:Checks | Where-Object { $_.Compliant -eq $true  }).Count
$nonCompliantCount = [int]@($global:Checks | Where-Object { $_.Compliant -eq $false }).Count
$naCount           = [int]@($global:Checks | Where-Object { $null -eq $_.Compliant  }).Count
$totalChecks       = [int]$global:Checks.Count
# Compliance % is calculated against APPLICABLE checks only (excludes N/A) so a host with
# many "not applicable" controls is not unfairly penalized.
$applicableCount   = $compliantCount + $nonCompliantCount
$compliancePct     = if ($applicableCount -gt 0) { [int][Math]::Round($compliantCount / $applicableCount * 100) } else { 0 }

# Severity breakdown: only count real failures, not N/A entries.
$critFail = [int]@($global:Checks | Where-Object { $_.Compliant -eq $false -and $_.Severity -eq 'CRITICAL' }).Count
$highFail = [int]@($global:Checks | Where-Object { $_.Compliant -eq $false -and $_.Severity -eq 'HIGH'     }).Count
$medFail  = [int]@($global:Checks | Where-Object { $_.Compliant -eq $false -and $_.Severity -eq 'MEDIUM'   }).Count
$lowFail  = [int]@($global:Checks | Where-Object { $_.Compliant -eq $false -and $_.Severity -eq 'LOW'      }).Count

$duration = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")

$riskColor  = if ($critFail -gt 0) { '#ff2d55' } elseif ($highFail -gt 0) { '#ff6b00' } elseif ($medFail -gt 0) { '#ffd60a' } else { '#30d158' }
# Gauge ring color based purely on compliance percentage
$gaugeColor = if ($compliancePct -ge 80) { '#00ff88' } elseif ($compliancePct -ge 60) { '#ff6b00' } else { '#ff2d55' }

# Pre-calculate gauge arc length (circumference = 2*pi*r = 2*3.14159*15.9155 = ~100)
$gaugeArc  = $compliancePct   # out of 100 = percentage of full circle
$gaugeGap  = 100 - $gaugeArc

function Get-SC { param([string]$s)
    switch ($s) { 'CRITICAL'{'#ff2d55'} 'HIGH'{'#ff6b00'} 'MEDIUM'{'#b8860b'} 'LOW'{'#1a7a44'} default{'#3d444d'} }
}

$catGroups   = $global:Checks | Group-Object Category | Sort-Object Name
$catBars     = ($catGroups | ForEach-Object {
    $grp      = $_
    $pass     = [int]@($grp.Group | Where-Object { $_.Compliant -eq $true  }).Count
    $fail     = [int]@($grp.Group | Where-Object { $_.Compliant -eq $false }).Count
    $total    = [int]($pass + $fail)
    $pct      = if ($total -gt 0) { [Math]::Round($pass / $total * 100) } else { 0 }
    $barPct   = [Math]::Min($pct, 100)
    $clr      = if ($pct -ge 90) { '#00ff88' } elseif ($pct -ge 60) { '#ffd60a' } else { '#ff6b00' }
    "<tr><td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px;white-space:nowrap'>$($grp.Name)</td><td style='color:#00ff88'>$pass</td><td style='color:#ff6b00'>$fail</td><td style='width:140px'><div style='background:#0d1117;border:1px solid #21262d;border-radius:3px;height:6px;width:120px;overflow:hidden'><div style='background:$clr;height:6px;border-radius:3px;width:${barPct}%;box-shadow:0 0 4px $clr'></div></div></td><td style='font-family:JetBrains Mono,monospace;color:$clr;font-size:10px'>$pct%</td></tr>"
}) -join "`n"

$tableRows = @(foreach ($c in ($global:Checks | Sort-Object @{e={if ($null -eq $_.Compliant) {2} elseif ($_.Compliant) {1} else {0}}},Severity)) {
    $sc    = Get-SC $c.Severity
    if ($null -eq $c.Compliant) {
        $comClr = '#8b949e'   # neutral grey for N/A
        $comTxt = 'N/A'
    } elseif ($c.Compliant) {
        $comClr = '#00ff88'
        $comTxt = 'PASS'
    } else {
        $comClr = '#ff6b00'
        $comTxt = 'FAIL'
    }
    $asClr = switch ($c.ApplyStatus) {
        'Applied+Verified'    { '#00ff88' }
        'Applied-NotVerified' { '#ffd60a' }
        'FAILED'              { '#ff2d55' }
        'AlreadyCompliant'    { '#00ff88' }
        'NotApplicable'       { '#8b949e' }
        default               { '#8b949e' }
    }
    $nm    = [System.Net.WebUtility]::HtmlEncode($c.Name)
    $desc  = [System.Net.WebUtility]::HtmlEncode($c.Description)
    # If N/A, append the skip reason to the description for transparency
    if ($null -eq $c.Compliant -and $c.PSObject.Properties['SkipReason'] -and $c.SkipReason) {
        $skipReasonEnc = [System.Net.WebUtility]::HtmlEncode($c.SkipReason)
        $desc = "$desc<br><span style='color:#8b949e;font-style:italic'>[N/A: $skipReasonEnc]</span>"
    }
    $ref   = [System.Net.WebUtility]::HtmlEncode($c.Reference)
    $rem   = [System.Net.WebUtility]::HtmlEncode($c.Remediation)
    $as    = [System.Net.WebUtility]::HtmlEncode($c.ApplyStatus)
    "<tr>
      <td style='font-family:JetBrains Mono,monospace;color:#8b949e;font-size:10px;white-space:nowrap'>$($c.ID)</td>
      <td><span class='badge' style='background:$sc'>$($c.Severity)</span></td>
      <td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px;white-space:nowrap'>$($c.Category)</td>
      <td style='font-size:12px'>$nm</td>
      <td style='color:#c9d1d9;font-size:11px;max-width:220px'>$desc</td>
      <td><span style='font-family:JetBrains Mono,monospace;color:$comClr;font-weight:700;font-size:11px'>$comTxt</span></td>
      <td style='font-family:JetBrains Mono,monospace;color:$asClr;font-size:10px'>$as</td>
      <td style='font-family:JetBrains Mono,monospace;color:#b0bec5;font-size:10px;max-width:160px'>$ref</td>
      <td><span class='rem-code'>$rem</span></td>
      <td style='font-family:JetBrains Mono,monospace;color:$(if($c.RebootRequired -eq "Yes"){"#ffd60a"}else{"#8b949e"});font-size:10px'>$($c.RebootRequired)</td>
    </tr>"
})

$modeColor = switch ($Mode) { 'Apply' { '#ff6b00' } 'Rollback' { '#a78bfa' } default { '#00d4ff' } }

# HTML-encoded variants of values that go into the report (defence-in-depth against
# unusual COMPUTERNAME / path content; in practice these are admin-controlled).
$_compNameEnc   = [System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)
$_backupPathEnc = [System.Net.WebUtility]::HtmlEncode($BackupPath)
$_outputPathEnc = [System.Net.WebUtility]::HtmlEncode($OutputPath)
$_modeEnc       = [System.Net.WebUtility]::HtmlEncode($Mode)
$_profileEnc    = [System.Net.WebUtility]::HtmlEncode($DeviceProfile)

# -- Pre-build profile summary HTML rows for the report -----------------------
$profileAppliedRows = ($global:ProfileApplied | ForEach-Object {
    "<tr><td style='width:16px;padding:8px 10px'><span style='color:#00ff88;font-family:JetBrains Mono,monospace;font-size:11px'>+</span></td>" +
    "<td style='padding:8px 12px;font-family:JetBrains Mono,monospace;font-size:11px;color:#c9d1d9'>$_</td></tr>"
}) -join ""

$profileSkippedRows = ($global:ProfileSkipped | ForEach-Object {
    "<tr><td style='width:16px;padding:8px 10px'><span style='color:#ff6b00;font-family:JetBrains Mono,monospace;font-size:11px'>-</span></td>" +
    "<td style='padding:8px 12px;font-family:JetBrains Mono,monospace;font-size:11px;color:#8b949e'>$_</td></tr>"
}) -join ""

$profileSectionHtml = if ($DeviceProfile -ne 'Custom') {
    $skippedBlock = if ($global:ProfileSkipped.Count -gt 0) {
        "<div style='margin-top:14px'>" +
        "<div style='font-family:JetBrains Mono,monospace;font-size:9px;color:#ff6b00;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px'>Skipped sections</div>" +
        "<table style='width:100%;border-collapse:collapse'>$profileSkippedRows</table></div>"
    } else { "" }

    $noteBlock = if ($global:ProfileNote) {
        "<div style='margin-top:14px;background:rgba(88,166,255,.06);border:1px solid rgba(88,166,255,.15);border-radius:5px;padding:10px 14px;" +
        "font-family:JetBrains Mono,monospace;font-size:11px;color:#8b949e;line-height:1.7'>" +
        "<span style='color:#58a6ff;font-weight:700'>NOTE &nbsp;</span>$($global:ProfileNote)</div>"
    } else { "" }

    "<div class='sec-hdr'><span class='sec-num'>02.5</span> Device Profile Applied: <span style='color:#a5d6ff'>$DeviceProfile</span></div>" +
    "<div class='panel'>" +
    "<div class='panel-title'>Applied sections</div>" +
    "<table style='width:100%;border-collapse:collapse'>$profileAppliedRows</table>" +
    $skippedBlock + $noteBlock +
    "</div>"
} else { "" }

# StrictMode disabled for here-string HTML generation to prevent false variable errors
Set-StrictMode -Off

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZavetSec-Harden // $_compNameEnc</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:#0a0d10;
  color:#c9d1d9;
  font-family:'Rajdhani',sans-serif;
  font-size:14px;
  line-height:1.6;
  min-height:100vh;
  overflow-x:hidden;
}
body::before{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,0.015) 2px,rgba(0,255,136,0.015) 4px);
  pointer-events:none;
  z-index:0;
}
body::after{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(0,255,136,0.07) 0%,transparent 65%);
  pointer-events:none;
  z-index:0;
}
.wrap{position:relative;z-index:1}
header{
  background:linear-gradient(180deg,#0d1117 0%,#0a0d10 100%);
  border-bottom:1px solid rgba(0,255,136,0.18);
  padding:22px 40px;
  display:flex;
  align-items:center;
  gap:24px;
}
.logo-block{display:flex;flex-direction:column;gap:2px}
.logo-name{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  font-weight:700;
  color:#00ff88;
  letter-spacing:3px;
  text-transform:uppercase;
}
.logo-title{
  font-family:'Share Tech Mono',monospace;
  font-size:22px;
  font-weight:400;
  color:#e6edf3;
  letter-spacing:2px;
}
.logo-title span{color:#00ff88}
.logo-cursor{
  color:#00ff88;
  animation:cur 1s step-end infinite;
}
@keyframes cur{0%,100%{opacity:1}50%{opacity:0}}
.header-meta{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  color:#8b949e;
  margin-top:4px;
}
.header-right{
  margin-left:auto;
  text-align:right;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;
  color:#8b949e;
  line-height:1.9;
}
.header-right .brand{color:#00ff88;font-weight:700;font-size:12px;letter-spacing:2px}
.dot-anim{display:inline-flex;gap:4px;vertical-align:middle;margin-left:6px}
.dot-anim span{
  width:5px;height:5px;border-radius:50%;
  background:#00ff88;
  animation:pulse 1.4s ease-in-out infinite;
}
.dot-anim span:nth-child(2){animation-delay:.2s}
.dot-anim span:nth-child(3){animation-delay:.4s}
@keyframes pulse{0%,80%,100%{opacity:.2;transform:scale(.8)}40%{opacity:1;transform:scale(1)}}
.main{padding:28px 40px;max-width:1820px;margin:0 auto}

/* -- SECTION HEADER -- */
.sec-hdr{
  display:flex;align-items:center;gap:10px;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:700;
  color:#00ff88;
  text-transform:uppercase;
  letter-spacing:2px;
  margin-bottom:14px;
  margin-top:28px;
  padding-bottom:7px;
  border-bottom:1px solid rgba(0,255,136,0.15);
}
.sec-num{
  background:rgba(0,255,136,0.12);
  border:1px solid rgba(0,255,136,0.3);
  color:#00ff88;
  padding:1px 7px;
  border-radius:3px;
  font-size:9px;
}

/* -- SCORE PANEL -- */
.score-panel{
  background:#0d1117;
  border:1px solid rgba(0,255,136,0.2);
  border-radius:10px;
  padding:24px 32px;
  margin-bottom:20px;
  display:flex;
  align-items:center;
  gap:32px;
  position:relative;
  overflow:hidden;
}
.score-panel::before{
  content:'';
  position:absolute;
  top:-60px;left:-60px;
  width:220px;height:220px;
  background:radial-gradient(circle,rgba(0,255,136,0.06) 0%,transparent 70%);
  pointer-events:none;
}
.gauge{flex:0 0 150px;height:150px;position:relative}
.gauge-pct{
  position:absolute;top:50%;left:50%;
  transform:translate(-50%,-50%);
  font-family:'JetBrains Mono',monospace;
  font-size:24px;font-weight:700;
  text-align:center;
  line-height:1.2;
}
.gauge-sub{font-size:9px;color:#8b949e;letter-spacing:1px;text-transform:uppercase}
.score-info{}
.score-label{
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;
  color:#8b949e;
  text-transform:uppercase;
  letter-spacing:2px;
  margin-bottom:4px;
}
.score-big{
  font-family:'JetBrains Mono',monospace;
  font-size:52px;font-weight:700;
  line-height:1;
  letter-spacing:-2px;
}
.score-sub{color:#8b949e;font-family:'JetBrains Mono',monospace;font-size:11px;margin-top:6px}
.sev-grid{
  margin-left:auto;
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  color:#8b949e;
  line-height:2.1;
  text-align:right;
}
.sev-row{display:flex;align-items:center;justify-content:flex-end;gap:8px}
.sev-val{font-weight:700;font-size:13px;min-width:20px;text-align:right}

/* -- STAT CARDS -- */
.stats{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin-bottom:20px}
.sc{
  background:#0d1117;
  border:1px solid #21262d;
  border-radius:8px;
  padding:14px 12px;
  position:relative;
  overflow:hidden;
  transition:border-color .2s;
}
.sc:hover{border-color:rgba(0,255,136,0.3)}
.sc::after{
  content:'';
  position:absolute;
  top:0;left:0;right:0;
  height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,255,136,0.3),transparent);
}
.sc .n{
  font-family:'JetBrains Mono',monospace;
  font-size:24px;font-weight:700;
  line-height:1.1;
}
.sc .l{
  font-family:'Rajdhani',sans-serif;
  font-size:9px;color:#8b949e;
  text-transform:uppercase;letter-spacing:1px;
  margin-top:4px;font-weight:600;
}

/* -- TWO-COL GRID -- */
.grid2{display:grid;grid-template-columns:3fr 2fr;gap:14px;margin-bottom:20px}
.panel{
  background:#0d1117;
  border:1px solid #21262d;
  border-radius:8px;
  padding:14px 18px;
}
.panel-title{
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;
  color:#8b949e;
  text-transform:uppercase;letter-spacing:1.5px;
  margin-bottom:10px;padding-bottom:6px;
  border-bottom:1px solid #21262d;
}

/* -- TABLES -- */
table{
  width:100%;border-collapse:collapse;
  background:#0d1117;
  border-radius:8px;overflow:hidden;
  border:1px solid #21262d;
  font-size:12px;
}
.tbl{width:100%;border-collapse:collapse;font-size:11px}
th{
  background:#010409;
  color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:9px;text-transform:uppercase;
  letter-spacing:1.2px;
  padding:9px 10px;
  text-align:left;font-weight:700;
  white-space:nowrap;
  border-bottom:1px solid rgba(0,255,136,0.12);
}
td{
  padding:8px 10px;
  border-top:1px solid #21262d;
  vertical-align:top;
  font-family:'Rajdhani',sans-serif;
}
tr:hover td{background:#0d1117;transition:background .15s}

/* -- BADGES -- */
.badge{
  display:inline-block;
  padding:2px 8px;
  border-radius:3px;
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;
  letter-spacing:.8px;
  color:#fff;
  white-space:nowrap;
}
.mode-badge{
  padding:2px 10px;border-radius:4px;
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;
  letter-spacing:1px;
  color:#000;
}

/* -- ALERT BOX -- */
.alert-box{
  background:rgba(255,45,85,0.08);
  border:1px solid rgba(255,45,85,0.35);
  border-radius:6px;
  padding:10px 16px;
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  color:#ff2d55;
  margin-bottom:16px;
}
.alert-box.warn{
  background:rgba(255,107,0,0.08);
  border-color:rgba(255,107,0,0.35);
  color:#ff6b00;
}

/* -- SEARCH BAR -- */
.search-bar{
  background:#0d1117;
  border:1px solid #21262d;
  border-radius:8px;
  padding:10px 14px;
  margin-bottom:12px;
  display:flex;gap:8px;
  align-items:center;flex-wrap:wrap;
}
.search-bar input{
  background:#010409;
  border:1px solid #30363d;
  border-radius:5px;
  color:#c9d1d9;
  padding:6px 12px;
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  flex:1;min-width:200px;
  outline:none;
  transition:border-color .2s;
}
.search-bar input:focus{border-color:rgba(0,255,136,0.4)}
.fbtn{
  background:#161b22;
  border:1px solid #30363d;
  border-radius:5px;
  color:#8b949e;
  padding:5px 12px;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;
  font-weight:700;
  cursor:pointer;
  letter-spacing:.5px;
  transition:all .15s;
}
.fbtn:hover{background:#21262d;color:#00ff88;border-color:rgba(0,255,136,0.3)}
.fbtn.active{background:rgba(0,255,136,0.1);border-color:rgba(0,255,136,0.4);color:#00ff88}

/* -- REMEDIATION CODE -- */
.rem-code{
  font-family:'JetBrains Mono',monospace;
  color:#7eb8ff;
  font-size:9px;
  max-width:220px;
  word-break:break-all;
  line-height:1.5;
  background:rgba(126,184,255,0.05);
  border-radius:3px;
  padding:2px 4px;
}

/* -- FOOTER -- */
footer{
  margin-top:40px;
  padding:16px 40px;
  border-top:1px solid rgba(0,255,136,0.1);
  color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;
  text-align:center;
  letter-spacing:.5px;
}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo-block">
    <div class="logo-name">ZavetSec<div class="dot-anim" style="display:inline-flex"><span></span><span></span><span></span></div></div>
    <div class="logo-title"><span>Harden</span><span class="logo-cursor">_</span> <span style="font-size:13px;color:#8b949e;font-weight:400">v1.3</span></div>
    <div class="header-meta">Windows Security Hardening Baseline &nbsp;//&nbsp; Host: $_compNameEnc &nbsp;//&nbsp; Mode: <span class="mode-badge" style="background:$modeColor">$_modeEnc</span> &nbsp;//&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;//&nbsp; Duration: $duration &nbsp;//&nbsp; Checks: $totalChecks</div>
  </div>
  <div class="header-right">
    <div class="brand">ZavetSec</div>
    <div>github.com/zavetsec</div>
    <div>CIS Benchmark | DISA STIG | MS Baseline</div>
  </div>
</header>

<div class="main">

  <!-- -- SCORE -- -->
  <div class="sec-hdr"><span class="sec-num">01</span> Compliance Overview</div>

  <div class="score-panel" style="border-color:rgba($(if($compliancePct -ge 80){'0,255,136'}elseif($compliancePct -ge 60){'255,107,0'}else{'255,45,85'}),0.3)">
    <div class="gauge">
      <svg viewBox="0 0 36 36" style="width:150px;height:150px;transform:rotate(-90deg)">
        <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#1c2128" stroke-width="3"/>
        <circle cx="18" cy="18" r="15.9155" fill="none" stroke-width="3"
          style="stroke:$gaugeColor;stroke-dasharray:$gaugeArc $gaugeGap;stroke-linecap:round;filter:drop-shadow(0 0 6px $gaugeColor)"/>
      </svg>
      <div class="gauge-pct" style="color:$gaugeColor">$compliancePct%<br><span class="gauge-sub">compliant</span></div>
    </div>
    <div class="score-info">
      <div class="score-label">Compliance Score</div>
      <div class="score-big" style="color:$gaugeColor">$compliancePct<span style="font-size:24px;color:#8b949e">%</span></div>
      <div class="score-sub">$compliantCount of $totalChecks checks passed &nbsp;|&nbsp; Mode: $Mode</div>
    </div>
    <div style="flex:1"></div>
    <div class="sev-grid">
      <div class="sev-row"><span>CRITICAL</span><span class="sev-val" style="color:#ff2d55">$critFail</span></div>
      <div class="sev-row"><span>HIGH</span><span class="sev-val" style="color:#ff6b00">$highFail</span></div>
      <div class="sev-row"><span>MEDIUM</span><span class="sev-val" style="color:#ffd60a">$medFail</span></div>
      <div class="sev-row"><span>LOW</span><span class="sev-val" style="color:#00ff88">$lowFail</span></div>
    </div>
  </div>

  <!-- -- STAT CARDS -- -->
  <div class="stats">
    <div class="sc"><div class="n" style="color:#00ff88">$compliantCount</div><div class="l">Passed</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$nonCompliantCount</div><div class="l">Failed</div></div>
    <div class="sc"><div class="n" style="color:#8b949e">$naCount</div><div class="l">N/A</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$critFail</div><div class="l">Critical</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$highFail</div><div class="l">High</div></div>
    <div class="sc"><div class="n" style="color:#ffd60a">$medFail</div><div class="l">Medium</div></div>
    <div class="sc"><div class="n" style="color:#00ff88">$lowFail</div><div class="l">Low</div></div>
    <div class="sc"><div class="n" style="color:#58a6ff">$($global:Applied)</div><div class="l">Applied</div></div>
    <div class="sc"><div class="n" style="color:#8b949e">$($global:Skipped)</div><div class="l">Already OK</div></div>
  </div>

  <!-- -- CATEGORY TABLE + COVERAGE -- -->
  <div class="sec-hdr"><span class="sec-num">02</span> Category Breakdown</div>
  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Compliance by Category</div>
      <table class="tbl">
        <thead><tr><th>Category</th><th style="color:#00ff88">Pass</th><th style="color:#ff6b00">Fail</th><th>Score</th><th>%</th></tr></thead>
        <tbody>$catBars</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Coverage &amp; Modules</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#8b949e;line-height:2.4;padding:4px 0">
        <div>Network Hardening <span style="color:$(if($SkipNetworkHardening){'#ff6b00'}else{'#00ff88'})">$(if($SkipNetworkHardening){'[SKIPPED]'}else{'[OK]'})</span></div>
        <div>Credential Protection <span style="color:$(if($SkipCredentialProtection){'#ff6b00'}else{'#00ff88'})">$(if($SkipCredentialProtection){'[SKIPPED]'}else{'[OK]'})</span></div>
        <div>PowerShell Hardening <span style="color:$(if($SkipPowerShell){'#ff6b00'}else{'#00ff88'})">$(if($SkipPowerShell){'[SKIPPED]'}else{'[OK]'})</span></div>
        <div>Audit Policy <span style="color:$(if($SkipAuditPolicy){'#ff6b00'}else{'#00ff88'})">$(if($SkipAuditPolicy){'[SKIPPED]'}else{'[OK]'})</span></div>
        <div>System Hardening <span style="color:#00ff88">[OK]</span></div>
        <div>Print Spooler Disable <span style="color:$(if($EnablePrintSpoolerDisable){'#00ff88'}else{'#8b949e'})">$(if($EnablePrintSpoolerDisable){'[ENABLED]'}else{'[OPT-IN]'})</span></div>
        <div>Profile: <span style="color:#a5d6ff">$_profileEnc</span></div>
        <div style="margin-top:4px;font-size:9px;color:#8b949e">Backup: $(if(Test-Path $BackupPath){"$_backupPathEnc"}else{'N/A'})</div>
        <div style="font-size:9px;color:#8b949e">Rollback: .\ZavetSec-Harden.ps1 -Mode Rollback -BackupPath &quot;...&quot;</div>
      </div>
    </div>
  </div>

  $profileSectionHtml

  <!-- -- CHECKS TABLE -- -->
  <div class="sec-hdr"><span class="sec-num">03</span> All Checks <span style="color:#8b949e;font-weight:400">($totalChecks)</span></div>

  $(if ($critFail -gt 0) { '<div class="alert-box">&#9888; ' + $critFail + ' CRITICAL check(s) failed &mdash; immediate remediation required</div>' })
  $(if ($highFail -gt 0) { '<div class="alert-box warn">&#9888; ' + $highFail + ' HIGH check(s) failed &mdash; review and remediate soon</div>' })

  <div class="search-bar">
    <input type="text" id="sb" placeholder="Filter by ID, name, category, severity..." oninput="ft()">
    <button class="fbtn" id="btn-fail" onclick="sf('FAIL')">FAIL only</button>
    <button class="fbtn" onclick="sf('critical')">CRITICAL</button>
    <button class="fbtn" onclick="sf('high')">HIGH</button>
    <button class="fbtn" onclick="sf('network')">Network</button>
    <button class="fbtn" onclick="sf('audit')">AuditPolicy</button>
    <button class="fbtn" onclick="sf('powershell')">PowerShell</button>
    <button class="fbtn" onclick="sf('credentials')">Credentials</button>
    <button class="fbtn" onclick="sf('')">Clear</button>
  </div>

  <table id="ft">
    <thead>
      <tr>
        <th>ID</th><th>Severity</th><th>Category</th><th>Check</th><th>Description</th>
        <th>Result</th><th>Apply Status</th><th>Reference</th><th>Remediation</th><th>Reboot</th>
      </tr>
    </thead>
    <tbody id="ftb">
      $($tableRows -join "`n")
    </tbody>
  </table>

</div><!-- /main -->

<footer>
  <span style="color:#00ff88;font-weight:700;letter-spacing:2px">ZAVETSEC</span>
  &nbsp;&bull;&nbsp; ZavetSec-Harden v1.4
  &nbsp;&bull;&nbsp; github.com/zavetsec
  &nbsp;&bull;&nbsp; Host: $_compNameEnc
  &nbsp;&bull;&nbsp; Mode: $_modeEnc
  &nbsp;&bull;&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  &nbsp;&bull;&nbsp; <span style="color:#ff2d55;font-weight:700">CONFIDENTIAL &mdash; SOC/DFIR USE ONLY</span>
</footer>
</div><!-- /wrap -->

<script>
var failOnly = false;
function ft() {
  var q = document.getElementById('sb').value.toLowerCase();
  var rows = document.getElementById('ftb').getElementsByTagName('tr');
  for (var i = 0; i < rows.length; i++) {
    var cells = rows[i].getElementsByTagName('td');
    if (cells.length === 0) { rows[i].style.display = ''; continue; }
    var resultCell = cells[5] ? cells[5].textContent.trim() : '';
    var isFail = resultCell === 'FAIL';
    var matchText = q === '' || rows[i].textContent.toLowerCase().indexOf(q) > -1;
    var show = matchText && (!failOnly || isFail);
    rows[i].style.display = show ? '' : 'none';
  }
}
function sf(v) {
  var btns = document.querySelectorAll('.fbtn');
  for (var b = 0; b < btns.length; b++) { btns[b].classList.remove('active'); }
  if (v === 'FAIL') {
    failOnly = !failOnly;
    document.getElementById('sb').value = '';
    if (failOnly) { document.getElementById('btn-fail').classList.add('active'); }
  } else {
    failOnly = false;
    document.getElementById('sb').value = v;
  }
  ft();
}
</script>
</body>
</html>
"@

# Ensure output directory exists
$_outDir = Split-Path $OutputPath -Parent
if ($_outDir -and -not (Test-Path $_outDir)) {
    $null = New-Item -Path $_outDir -ItemType Directory -Force
}

# Save report
try {
    # Use UTF8NoBOM encoding -- PS5.1 Out-File UTF8 adds BOM which breaks browser rendering
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)
    Write-Host "  [OK] HTML report saved: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "  [XX] Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
    $OutputPath = Join-Path $env:TEMP "ZavetSecHardening_${env:COMPUTERNAME}_$_stamp.html"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)
    Write-Host "  [OK] Report saved to TEMP: $OutputPath" -ForegroundColor Yellow
}

# StrictMode remains Off (set at script start) -- avoids null-property pitfalls in cleanup blocks

$sep = "-" * 64
Write-Host ""; Write-Host $sep -ForegroundColor DarkGray
Write-Host "  SET-ZAVETSEC HARDENING BASELINE COMPLETE" -ForegroundColor White
Write-Host $sep -ForegroundColor DarkGray
Write-Host "  Host         : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Mode         : $Mode" -ForegroundColor $(if ($isApply) { 'Yellow' } else { 'Cyan' })
Write-Host "  Duration     : $duration" -ForegroundColor Gray
Write-Host "  Checks       : $totalChecks" -ForegroundColor Gray
Write-Host ""
Write-Host "  PASSED       : $compliantCount" -ForegroundColor Green
Write-Host "  FAILED       : $nonCompliantCount" -ForegroundColor $(if ($nonCompliantCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Compliance   : $compliancePct%" -ForegroundColor $(if ($compliancePct -ge 90) { 'Green' } elseif ($compliancePct -ge 60) { 'Yellow' } else { 'Red' })
Write-Host ""
Write-Host "  CRITICAL fail: $critFail" -ForegroundColor $(if ($critFail -gt 0) { 'Red' } else { 'Green' })
Write-Host "  HIGH fail    : $highFail" -ForegroundColor $(if ($highFail -gt 0) { 'Red' } else { 'Green' })
Write-Host "  MEDIUM fail  : $medFail" -ForegroundColor $(if ($medFail -gt 0) { 'Yellow' } else { 'Green' })
if ($isApply) {
    Write-Host ""
    Write-Host "  Applied      : $($global:Applied)" -ForegroundColor Cyan
    Write-Host "  Already OK   : $($global:Skipped)" -ForegroundColor DarkGray
    Write-Host "  Apply Failed : $($global:Failed)" -ForegroundColor $(if ($global:Failed -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Backup       : $BackupPath" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Report: $OutputPath" -ForegroundColor Cyan
Write-Host $sep -ForegroundColor DarkGray

$rebootNeeded = @($global:Checks | Where-Object { $_.RebootRequired -eq 'Yes' -and $_.Compliant -eq $false }).Count
if ($isApply -and $rebootNeeded -gt 0) {
    Write-Host ""
    Write-Host "  [!] $rebootNeeded setting(s) require a REBOOT to take effect." -ForegroundColor Yellow
    Write-Host "      (Credential Guard, DEP, PS v2 disable, SMBv1 client driver)" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host ""
Write-Host "  Report saved : $OutputPath" -ForegroundColor Cyan
Write-Host "  Backup saved : $BackupPath"  -ForegroundColor Cyan
Write-Host ""

if (-not $NonInteractive) {
    # Ask to open report - works regardless of how the script was launched
    Write-Host "  Open HTML report in browser? [Y/N]: " -ForegroundColor Yellow -NoNewline
    $open = [Console]::ReadLine()
    if ($open -match '^[Yy]') {
        Start-Process $OutputPath
        Write-Host "  Opened." -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
    $null = [Console]::ReadLine()
} else {
    Write-Host "  [-NonInteractive] Done. Report: $OutputPath" -ForegroundColor DarkGray
}
