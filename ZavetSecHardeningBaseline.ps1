#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSecHardeningBaseline - Windows security hardening baseline by ZavetSec.
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

.PARAMETER Mode
    'Audit'  - Check settings, report only, no changes (default)
    'Apply'  - Apply all hardening settings
    'Rollback' - Revert changes made by a previous Apply (reads backup)
.PARAMETER BackupPath
    Path for settings backup JSON (used by Apply and Rollback).
    Default = Desktop\HardeningBackup_<timestamp>.json
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
    .\ZavetSecHardeningBaseline.ps1 -Mode Audit

    # Apply all hardening:
    .\ZavetSecHardeningBaseline.ps1 -Mode Apply

    # Apply with custom backup:
    .\ZavetSecHardeningBaseline.ps1 -Mode Apply -BackupPath C:\DFIR\backup.json

    # Rollback:
    .\ZavetSecHardeningBaseline.ps1 -Mode Rollback -BackupPath C:\DFIR\backup.json

    # Partial apply (skip audit policy):
    .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipAuditPolicy
.NOTES
    ================================================================
    ZavetSec | https://github.com/zavetsec
    Script   : ZavetSecHardeningBaseline
    Version  : 1.1
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
    [ValidateSet('Audit','Apply','Rollback')]
    [string]$Mode                      = 'Audit',
    [string]$BackupPath                = '',
    [string]$OutputPath                = '',
    [switch]$SkipAuditPolicy,
    [switch]$SkipNetworkHardening,
    [switch]$SkipPowerShell,
    [switch]$SkipCredentialProtection,
    [switch]$EnablePrintSpoolerDisable,
    [switch]$NonInteractive  # Suppress all prompts (for PsExec/remote/scheduled task use)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$global:StartTime = Get-Date
$global:Checks    = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:Backup    = [ordered]@{}
$global:Applied   = 0
$global:Skipped   = 0
$global:Failed    = 0
$isApply          = $Mode -eq 'Apply'
$isAudit          = $Mode -eq 'Audit'
$isRollback       = $Mode -eq 'Rollback'

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
        [scriptblock]$CheckScript,   # Returns $true if compliant
        [scriptblock]$ApplyScript,
        [scriptblock]$BackupScript,
        [string]$Reference    = '',     # CIS/MITRE reference
        [string]$Remediation  = '',     # Manual fix command
        [string]$RebootRequired = 'No'
    )

    $compliant  = $false
    $checkError = ''
    $applyStatus= ''

    # --- CHECK ---
    try {
        $compliant = & $CheckScript
    } catch {
        $checkError = $_.ToString()
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
        try {
            Write-Apply "  Applying: $Name"
            & $ApplyScript
            $applyStatus = 'Applied'
            $global:Applied++

            # Verify
            $verifyOk = & $CheckScript
            if ($verifyOk) {
                Write-Pass "  Verified OK"
                $applyStatus = 'Applied+Verified'
            } else {
                Write-Fail "  Applied but verify failed (may need reboot)"
                $applyStatus = 'Applied-NotVerified'
            }
        } catch {
            Write-Err "  Apply failed: $_"
            $applyStatus = "FAILED: $_"
            $global:Failed++
        }
    } elseif ($isApply -and $compliant) {
        $applyStatus = 'AlreadyCompliant'
        $global:Skipped++
    }

    # --- POST-APPLY RE-CHECK ---
    # Обновляем $compliant актуальным состоянием после применения,
    # чтобы отчёт отражал результат Apply, а не состояние до него.
    if ($isApply -and $applyStatus -notin @('', 'AlreadyCompliant')) {
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
# ROLLBACK MODE
# -------------------------------------------------------
if ($isRollback) {
    Write-Phase "ROLLBACK MODE"

    # --- Interactive backup selection if path not given or not found ---
    if ([string]::IsNullOrEmpty($BackupPath) -or -not (Test-Path $BackupPath)) {
        if (-not $NonInteractive) {
            # Search for backup files in script directory
            $backupFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter 'HardeningBackup_*.json' -File |
                             Sort-Object LastWriteTime -Descending)

            if ($backupFiles.Count -eq 0) {
                Write-Err "No backup files found in: $PSScriptRoot"
                Write-Host "  Run '-Mode Apply' first to create a backup." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
                $null = [Console]::ReadLine()
                exit 1
            }

            Write-Host ""
            Write-Host "  Available backups (newest first):" -ForegroundColor Cyan
            Write-Host ""
            for ($i = 0; $i -lt $backupFiles.Count; $i++) {
                $f = $backupFiles[$i]
                Write-Host ("  [{0,2}]  {1}  [{2}]" -f ($i + 1), $f.Name, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Gray
            }
            Write-Host ""
            Write-Host ("  Select backup [1-{0}]: " -f $backupFiles.Count) -ForegroundColor Yellow -NoNewline
            $sel = [Console]::ReadLine()
            $selIdx = 0
            if (-not [int]::TryParse($sel.Trim(), [ref]$selIdx) -or $selIdx -lt 1 -or $selIdx -gt $backupFiles.Count) {
                Write-Err "Invalid selection: $sel"
                Write-Host ""
                Write-Host "  Press ENTER to exit..." -ForegroundColor DarkGray
                $null = [Console]::ReadLine()
                exit 1
            }
            $BackupPath = $backupFiles[$selIdx - 1].FullName
            Write-Host ""
            Write-Info "Selected: $BackupPath"
        } else {
            Write-Err "Backup file not found: $BackupPath"
            Write-Host "  Specify correct path: -BackupPath C:\path\to\backup.json" -ForegroundColor Yellow
            exit 1
        }
    }
    $bkData  = Get-Content $BackupPath -Raw | ConvertFrom-Json
    $bkCount = 0
    $bkFail  = 0

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
                Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -EA SilentlyContinue | Out-Null
                Write-Pass "PSv2 re-enabled  (reboot required)"
                $bkCount++; continue
            }

            # NET-007: NetBIOS adapter map { adapterPath = value }
            if ($id -eq 'NET-007') {
                foreach ($adp in $bkv.PSObject.Properties) {
                    Set-ItemProperty -Path $adp.Name -Name 'NetbiosOptions' -Value $adp.Value -Force -EA SilentlyContinue
                }
                Write-Pass "NetBIOS adapter options restored"
                $bkCount++; continue
            }

            # Composite entries (NET-005/006 .Req/.Enable, CRED-006 .Srv/.Cli, etc)
            # Must check AFTER standard single-key check to avoid false matches.
            # Null-safe: only inspect sub-properties if $bkv itself is an object.
            $isComposite = $false
            if ($bkv -is [System.Management.Automation.PSCustomObject]) {
                # Standard single Backup-RegValue: has .Existed directly on $bkv — handle first
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

                # Composite: sub-keys each containing their own Backup-RegValue object
                $subEntries = @($bkv.PSObject.Properties | Where-Object {
                    $_.Value -ne $null -and
                    $_.Value -is [System.Management.Automation.PSCustomObject] -and
                    ($_.Value.PSObject.Properties.Name -contains 'Path') })
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
    exit 0
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
Write-Host '    Windows Security Hardening Baseline v1.0    ' -ForegroundColor White
Write-Host '    CIS Benchmark | DISA STIG | MS Security Baseline' -ForegroundColor DarkGray
Write-Host '    https://github.com/zavetsec                 ' -ForegroundColor DarkGray
Write-Host ''

# -------------------------------------------------------
# ADMIN CHECK
# -------------------------------------------------------
Write-Host "  ============================================================" -ForegroundColor DarkCyan
Write-Host "    Script : ZavetSecHardeningBaseline v1.0" -ForegroundColor Cyan
Write-Host "    Mode   : $Mode" -ForegroundColor $(if ($isApply) { 'Yellow' } else { 'Gray' })
Write-Host "    Host   : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "    Time   : $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  ============================================================" -ForegroundColor DarkCyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Err "Not running as Administrator. Apply mode requires elevation."
    if ($isApply) {
        Write-Host "  Restart PowerShell as Administrator and re-run." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  Audit mode - some checks may fail without admin rights." -ForegroundColor Yellow
}

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

# ===========================================================
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
        # Also set via Connections key
        Set-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'DefaultConnectionSettings' 0 -Type Binary
        $svc = Get-Service 'WinHttpAutoProxySvc' -EA SilentlyContinue
        if ($svc) { Stop-Service 'WinHttpAutoProxySvc' -Force -EA SilentlyContinue }
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
        $bkMap = @{}
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | ForEach-Object {
            $bkMap[$_.PSPath] = (Get-RegValue $_.PSPath 'NetbiosOptions' 0)
        }
        return $bkMap
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
        return ($v1 -eq 1) -and ($v2 -ge 1)
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
        return $svc -and $svc.StartType -in @('Disabled') -and $svc.Status -eq 'Stopped'
    } `
    -BackupScript {
        $svc = Get-Service 'RemoteRegistry' -EA SilentlyContinue
        return @{ StartType = $svc.StartType.ToString(); Status = $svc.Status.ToString() }
    } `
    -ApplyScript {
        Stop-Service 'RemoteRegistry' -Force -EA SilentlyContinue
        Set-Service  'RemoteRegistry' -StartupType Disabled -EA SilentlyContinue
    }

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
    -Description 'Credential Guard uses VBS to protect NTLM hashes and Kerberos tickets from extraction' `
    -Reference 'MITRE T1003 | Requires UEFI + Secure Boot + VBS' `
    -Remediation 'GPO: Computer Config > Admin Templates > System > Device Guard > Turn On VBS + Credential Guard (LsaCfgFlags=1). Requires UEFI + Secure Boot.' `
    -RebootRequired 'Yes' `
    -CheckScript {
        $lsaCfg = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 99
        $vbsEnab = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 99
        return ($lsaCfg -ge 1) -and ($vbsEnab -eq 1)
    } `
    -BackupScript {
        @{
            LsaCfgFlags = (Backup-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags')
            VBS         = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity')
            CGPlatform  = (Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags')
        }
    } `
    -ApplyScript {
        $dgKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        if (-not (Test-Path $dgKey)) { $null = New-Item $dgKey -Force }
        Set-RegValue $dgKey 'EnableVirtualizationBasedSecurity'            1
        Set-RegValue $dgKey 'RequirePlatformSecurityFeatures'              3  # Secure Boot + DMA
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
        return ($vSrv -band 0x20000000) -and ($vSrv -band 0x80000000) -and
               ($vCli -band 0x20000000) -and ($vCli -band 0x80000000)
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
        if ($feature) { return $feature.State -eq 'Disabled' }
        # Fallback: check if powershell -version 2 fails
        return $false
    } `
    -BackupScript { return @{ PSv2Feature = 'WasEnabled' } } `
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
    # Reads audit status by GUID using /r CSV mode.
    # auditpol /r output structure (Russian Windows):
    #   [0] = header line  (localized column names)
    #   [1] = empty string
    #   [2] = data line    (KOMPUTER,Sistema,...,{GUID},Uspeh i sboi,)
    #   [3] = empty string
    # Col4 (index 4) = Inclusion Setting - localized text:
    #   empty string     = No Auditing
    #   contains space   = Success AND Failure (all locales: "Uspeh i sboi" / "Success and Failure")
    #   single word      = Success OR Failure only
    $ap = "$env:SystemRoot\System32\auditpol.exe"
    $out = & $ap /get /subcategory:"$Guid" /r 2>&1
    if ($LASTEXITCODE -ne 0 -or $out.Count -lt 3) { return 'Not Configured' }

    # Find the data line: first non-empty line that contains the GUID
    $dataLine = $null
    foreach ($line in $out) {
        $s = $line.ToString()
        if ($s -match [regex]::Escape($Guid)) { $dataLine = $s; break }
    }
    if (-not $dataLine) { return 'Not Configured' }

    $cols = $dataLine -split ','
    if ($cols.Count -lt 5) { return 'Not Configured' }
    $col4 = $cols[4].Trim()

    if ([string]::IsNullOrWhiteSpace($col4)) { return 'No Auditing' }
    if ($col4 -match ' ')                    { return 'Success,Failure' }

    # Single word - probe to distinguish Success vs Failure
    $null = & $ap /set /subcategory:"$Guid" /success:enable /failure:disable 2>&1
    $probe = & $ap /get /subcategory:"$Guid" /r 2>&1
    $probeLine = $null
    foreach ($line in $probe) {
        $s = $line.ToString()
        if ($s -match [regex]::Escape($Guid)) { $probeLine = $s; break }
    }
    if ($probeLine) {
        $pcols = $probeLine -split ','
        if ($pcols.Count -ge 5 -and $pcols[4].Trim() -eq $col4) {
            return 'Success'
        } else {
            $null = & $ap /set /subcategory:"$Guid" /success:disable /failure:enable 2>&1
            return 'Failure'
        }
    }
    return 'Not Configured'
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
            if (`$want -eq 'Success,Failure') { return `$current -eq 'Success,Failure' }
            if (`$want -eq 'Success')         { return `$current -in @('Success','Success,Failure') }
            if (`$want -eq 'Failure')         { return `$current -in @('Failure','Success,Failure') }
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
Test-And-Set -ID 'AUD-028' -Category 'AuditPolicy' -Severity 'HIGH' `
    -Name 'Include command line in Process Creation events (4688)' `
    -Description 'Without this, 4688 events do not include the executed command line - blind spot for detection' `
    -Reference 'MS KB3004375 | CIS L1' `
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
        $dep = & bcdedit /enum '{current}' 2>&1 | Where-Object { $_ -match 'nx' }
        return $dep -match 'AlwaysOn'
    } `
    -BackupScript { return @{ DEP = 'OptIn' } } `
    -ApplyScript  { & bcdedit /set '{current}' nx AlwaysOn 2>&1 | Out-Null }

# --- Event Log Sizes + Retention (overwrite, no archive files) ---
Test-And-Set -ID 'SYS-006' -Category 'System' -Severity 'HIGH' `
    -Name 'Event Log sizes: Security 1GB, System/App 256MB; retention=overwrite, no archive files' `
    -Description 'Default log sizes are too small. Retention set to overwrite (not archive) to prevent disk fill-up on end-user machines. AutoBackupLogFiles disabled explicitly.' `
    -Reference 'CIS L1' `
    -Remediation 'wevtutil sl Security /ms:1073741824 /rt:false /ab:false && wevtutil sl System /ms:268435456 /rt:false /ab:false && wevtutil sl Application /ms:268435456 /rt:false /ab:false' `
    -CheckScript {
        $secSize   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize' 0
        $retention = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'Retention' 99
        $autoBack  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'AutoBackupLogFiles' 99
        # Compliant: size >= 1GB, Retention=0 (overwrite), AutoBackupLogFiles absent or 0
        return ($secSize -ge 1073741824) -and ($retention -eq 0) -and ($autoBack -ne 1)
    } `
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
    -ApplyScript {
        # --- Sizes ---
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'MaxSize' 1073741824  # 1 GB
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'MaxSize' 268435456   # 256 MB
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'MaxSize' 268435456   # 256 MB
        # --- Retention = 0 (overwrite oldest events when full, no archive files) ---
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'Retention' 0
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'Retention' 0
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'Retention' 0
        # --- AutoBackupLogFiles = 0 (explicitly disable archive file creation) ---
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'AutoBackupLogFiles' 0
        # --- Apply via wevtutil as well (covers modern evtx channels) ---
        # /rt:false = overwrite when full; /ab:false = no auto-archive
        & wevtutil sl Security    /ms:1073741824 /rt:false /ab:false 2>&1 | Out-Null
        & wevtutil sl System      /ms:268435456  /rt:false /ab:false 2>&1 | Out-Null
        & wevtutil sl Application /ms:268435456  /rt:false /ab:false 2>&1 | Out-Null
    }

# --- Secure DNS over HTTPS ---
Test-And-Set -ID 'SYS-007' -Category 'System' -Severity 'MEDIUM' `
    -Name 'Enable Encrypted DNS (DoH) policy' `
    -Description 'Prevent DNS-based MITM and C2 over DNS by enforcing DoH where supported' `
    -Reference 'MITRE T1071.004' `
    -Remediation 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DoHPolicy /t REG_DWORD /d 2 /f  (2=Allow DoH, 3=Require DoH)' `
    -CheckScript {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 99
        return $v -ge 2  # 2=Allow, 3=Require
    } `
    -BackupScript { Backup-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' } `
    -ApplyScript  { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 2 }

# --- Disable Print Spooler (optional) ---
if ($EnablePrintSpoolerDisable) {
    Test-And-Set -ID 'SYS-008' -Category 'System' -Severity 'HIGH' `
        -Name 'Disable Print Spooler (PrintNightmare mitigation)' `
        -Description 'Print Spooler (CVE-2021-34527) allows SYSTEM code execution; disable if no printing needed' `
        -Reference 'CVE-2021-34527 | MITRE T1547.010' `
    -Remediation 'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled' `
        -CheckScript {
            $svc = Get-Service 'Spooler' -EA SilentlyContinue
            return $svc -and $svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped'
        } `
        -BackupScript {
            $svc = Get-Service 'Spooler' -EA SilentlyContinue
            return @{ StartType = $svc.StartType.ToString() }
        } `
        -ApplyScript {
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

$compliantCount    = [int]($global:Checks | Where-Object { $_.Compliant -eq $true  }).Count
$nonCompliantCount = [int]($global:Checks | Where-Object { $_.Compliant -eq $false }).Count
$totalChecks       = [int]$global:Checks.Count
$compliancePct     = if ($totalChecks -gt 0) { [int][Math]::Round($compliantCount / $totalChecks * 100) } else { 0 }

$critFail = [int]($global:Checks | Where-Object { -not $_.Compliant -and $_.Severity -eq 'CRITICAL' }).Count
$highFail = [int]($global:Checks | Where-Object { -not $_.Compliant -and $_.Severity -eq 'HIGH'     }).Count
$medFail  = [int]($global:Checks | Where-Object { -not $_.Compliant -and $_.Severity -eq 'MEDIUM'   }).Count
$lowFail  = [int]($global:Checks | Where-Object { -not $_.Compliant -and $_.Severity -eq 'LOW'      }).Count

$duration = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")

$riskColor = if ($critFail -gt 0) { '#ff2d55' } elseif ($highFail -gt 0) { '#ff6b00' } elseif ($medFail -gt 0) { '#ffd60a' } else { '#30d158' }

# Pre-calculate gauge arc length (circumference = 2*pi*r = 2*3.14159*15.9155 = ~100)
$gaugeArc  = $compliancePct   # out of 100 = percentage of full circle
$gaugeGap  = 100 - $gaugeArc

function Get-SC { param([string]$s)
    switch ($s) { 'CRITICAL'{'#ff2d55'} 'HIGH'{'#ff6b00'} 'MEDIUM'{'#b8860b'} 'LOW'{'#1a7a44'} default{'#3d444d'} }
}

$catGroups   = $global:Checks | Group-Object Category | Sort-Object Name
$catBars     = ($catGroups | ForEach-Object {
    $grp      = $_
    $pass     = [int]($grp.Group | Where-Object { $_.Compliant -eq $true  }).Count
    $fail     = [int]($grp.Group | Where-Object { $_.Compliant -eq $false }).Count
    $total    = [int]($pass + $fail)
    $pct      = if ($total -gt 0) { [Math]::Round($pass / $total * 100) } else { 0 }
    $barPct   = [Math]::Min($pct, 100)
    $clr      = if ($pct -ge 90) { '#00ff88' } elseif ($pct -ge 60) { '#ffd60a' } else { '#ff6b00' }
    "<tr><td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px;white-space:nowrap'>$($grp.Name)</td><td style='color:#00ff88'>$pass</td><td style='color:#ff6b00'>$fail</td><td style='width:140px'><div style='background:#0d1117;border:1px solid #21262d;border-radius:3px;height:6px;width:120px;overflow:hidden'><div style='background:$clr;height:6px;border-radius:3px;width:${barPct}%;box-shadow:0 0 4px $clr'></div></div></td><td style='font-family:JetBrains Mono,monospace;color:$clr;font-size:10px'>$pct%</td></tr>"
}) -join "`n"

$tableRows = @(foreach ($c in ($global:Checks | Sort-Object @{e={if ($_.Compliant) {1} else {0}}},Severity)) {
    $sc    = Get-SC $c.Severity
    $comClr= if ($c.Compliant) { '#00ff88' } else { '#ff6b00' }
    $comTxt= if ($c.Compliant) { 'PASS' } else { 'FAIL' }
    $asClr = switch ($c.ApplyStatus) { 'Applied+Verified'{'#00ff88'} 'Applied-NotVerified'{'#ffd60a'} 'FAILED'{'#ff2d55'} 'AlreadyCompliant'{'#00ff88'} default{'#8b949e'} }
    $nm    = [System.Net.WebUtility]::HtmlEncode($c.Name)
    $desc  = [System.Net.WebUtility]::HtmlEncode($c.Description)
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

# StrictMode disabled for here-string HTML generation to prevent false variable errors
Set-StrictMode -Off

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZavetSec Hardening Baseline // $env:COMPUTERNAME</title>
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

/* ── SECTION HEADER ── */
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

/* ── SCORE PANEL ── */
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

/* ── STAT CARDS ── */
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

/* ── TWO-COL GRID ── */
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

/* ── TABLES ── */
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

/* ── BADGES ── */
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

/* ── ALERT BOX ── */
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

/* ── SEARCH BAR ── */
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

/* ── REMEDIATION CODE ── */
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

/* ── FOOTER ── */
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
    <div class="logo-title">Hardening<span>Baseline</span><span class="logo-cursor">_</span> <span style="font-size:13px;color:#8b949e;font-weight:400">v1.1</span></div>
    <div class="header-meta">Windows Security Hardening &nbsp;//&nbsp; Host: $env:COMPUTERNAME &nbsp;//&nbsp; Mode: <span class="mode-badge" style="background:$modeColor">$Mode</span> &nbsp;//&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;//&nbsp; Duration: $duration &nbsp;//&nbsp; Checks: $totalChecks</div>
  </div>
  <div class="header-right">
    <div class="brand">ZavetSec</div>
    <div>github.com/zavetsec</div>
    <div>CIS Benchmark | DISA STIG | MS Baseline</div>
  </div>
</header>

<div class="main">

  <!-- ── SCORE ── -->
  <div class="sec-hdr"><span class="sec-num">01</span> Compliance Overview</div>

  <div class="score-panel" style="border-color:rgba($(if($compliancePct -ge 90){'0,255,136'}elseif($compliancePct -ge 60){'255,214,10'}else{'255,45,85'}),0.3)">
    <div class="gauge">
      <svg viewBox="0 0 36 36" style="width:150px;height:150px;transform:rotate(-90deg)">
        <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#1c2128" stroke-width="3"/>
        <circle cx="18" cy="18" r="15.9155" fill="none" stroke-width="3"
          style="stroke:$riskColor;stroke-dasharray:$gaugeArc $gaugeGap;stroke-linecap:round;filter:drop-shadow(0 0 4px $riskColor)"/>
      </svg>
      <div class="gauge-pct" style="color:$riskColor">$compliancePct%<br><span class="gauge-sub">compliant</span></div>
    </div>
    <div class="score-info">
      <div class="score-label">Compliance Score</div>
      <div class="score-big" style="color:$riskColor">$compliancePct<span style="font-size:24px;color:#8b949e">%</span></div>
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

  <!-- ── STAT CARDS ── -->
  <div class="stats">
    <div class="sc"><div class="n" style="color:#00ff88">$compliantCount</div><div class="l">Passed</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$nonCompliantCount</div><div class="l">Failed</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$critFail</div><div class="l">Critical</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$highFail</div><div class="l">High</div></div>
    <div class="sc"><div class="n" style="color:#ffd60a">$medFail</div><div class="l">Medium</div></div>
    <div class="sc"><div class="n" style="color:#00ff88">$lowFail</div><div class="l">Low</div></div>
    <div class="sc"><div class="n" style="color:#58a6ff">$($global:Applied)</div><div class="l">Applied</div></div>
    <div class="sc"><div class="n" style="color:#8b949e">$($global:Skipped)</div><div class="l">Already OK</div></div>
  </div>

  <!-- ── CATEGORY TABLE + COVERAGE ── -->
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
        <div style="margin-top:10px;font-size:9px;color:#8b949e">Backup: $(if(Test-Path $BackupPath){"$BackupPath"}else{'N/A'})</div>
        <div style="font-size:9px;color:#8b949e">Rollback: .\ZavetSecHardeningBaseline.ps1 -Mode Rollback -BackupPath &quot;...&quot;</div>
      </div>
    </div>
  </div>

  <!-- ── CHECKS TABLE ── -->
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
  &nbsp;&bull;&nbsp; ZavetSecHardeningBaseline v1.1
  &nbsp;&bull;&nbsp; github.com/zavetsec
  &nbsp;&bull;&nbsp; Host: $env:COMPUTERNAME
  &nbsp;&bull;&nbsp; Mode: $Mode
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
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  [OK] HTML report saved: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "  [XX] Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
    $OutputPath = Join-Path $env:TEMP "ZavetSecHardening_${env:COMPUTERNAME}_$_stamp.html"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "  [OK] Report saved to TEMP: $OutputPath" -ForegroundColor Yellow
}

# Restore StrictMode
Set-StrictMode -Version Latest

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

$rebootNeeded = ($global:Checks | Where-Object { $_.RebootRequired -eq 'Yes' -and -not $_.Compliant }).Count
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
