#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSecWindowsDefaults v1.3 - Reset Windows security settings to clean defaults.
.DESCRIPTION
    Resets all settings touched by ZavetSec-Harden v1.3 back to Windows
    out-of-box defaults. Does NOT require a backup file.

    Use this when:
      - The JSON backup from ZavetSec-Harden is lost
      - The machine was hardened by a third-party tool (not this script)
      - You need a clean baseline before re-applying hardening
      - You broke something with hardening (RDP, Kerberos, SMB) and need
        a fast, deterministic restore that does not depend on JSON state

    Resets coverage (1:1 with ZavetSec-Harden v1.3 IDs):
      NETWORK    : NET-001..NET-014
                   - Re-enables LLMNR, mDNS, WPAD, NBT-NS, LMHOSTS
                   - Re-enables SMBv1 server key (NOT client driver - reboot)
                   - Removes SMB signing requirements
                   - Removes anonymous enumeration restrictions
                   - Removes NullSession restrictions
                   - Restores IP source routing default
                   - Restores ICMP redirect acceptance
                   - Restores Remote Registry to Manual (stopped)
      CREDENTIALS: CRED-001..CRED-011
                   - Removes WDigest override
                   - Removes LSA RunAsPPL
                   - Removes Credential Guard policy keys
                   - Restores LmCompatibilityLevel to 3 (Windows default)
                   - Removes NoLMHash restriction
                   - Removes NTLM min session security overrides
                   - Removes DisableDomainCreds
                   - Removes CredSSP AllowEncryptionOracle (RDP fix)
                   - Restores Kerberos SupportedEncryptionTypes default
                   - Removes Remote Credential Guard policy
                   - Removes Netlogon hardening
      POWERSHELL : PS-001..PS-005
                   - Disables ScriptBlock / Module / Transcription logging
                   - Removes ExecutionPolicy machine override
                   - Re-enables PowerShell v2 feature (reboot required)
      AUDIT      : AUD-001..AUD-029
                   - Resets all 27 subcategories to "No Auditing"
                   - Removes ProcessCreationIncludeCmdLine
                   - Removes SCENoApplyLegacyAuditPolicy
      SYSTEM     : SYS-001..SYS-015
                   - Restores UAC defaults
                   - Re-enables AutoRun/AutoPlay
                   - Removes RDP NLA / encryption-level overrides
                   - Restores DEP to OptIn (reboot)
                   - Restores Event Log sizes to 20 MB Windows default,
                     overwrite-when-full retention
                   - Removes DoH policy
                   - Re-enables Print Spooler (Manual)
                   - Re-enables DNS Client multicast
                   - Removes LSASS audit/PPL extras
                   - Removes Wintrust EnableCertPaddingCheck
                   - Removes NTLM audit policy
                   - Removes NullSessionFallback restriction

.PARAMETER OutputPath
    HTML report path. Default = ScriptDir\ZavetSecDefaults_<timestamp>.html
.PARAMETER NonInteractive
    Suppress all prompts (for PsExec / remote / scheduled task use).
.PARAMETER SkipAuditPolicy
    Skip resetting auditpol subcategories. Use on domain-joined hosts where
    audit policy is managed via GPO -- otherwise local reset will be re-applied
    by GPO refresh anyway.
.EXAMPLE
    # Interactive reset with confirmation
    .\WindowsDefaults.ps1

    # Silent reset (PsExec / automation)
    .\WindowsDefaults.ps1 -NonInteractive

    # Custom report path, skip auditpol
    .\WindowsDefaults.ps1 -OutputPath C:\Reports\defaults.html -SkipAuditPolicy
.NOTES
    ================================================================
    ZavetSec | https://github.com/zavetsec
    Script   : ZavetSecWindowsDefaults v1.3
    Author   : ZavetSec
    License  : MIT
    ================================================================
    Companion to ZavetSec-Harden.ps1 v1.3
    Use ZavetSec-Harden -Mode Rollback when JSON backup exists.
    Use THIS script when backup is lost or machine was hardened externally.
    ================================================================
    WARNING : This script removes hardening. Run only when intentional.
    Reboot  : Required for SMBv1 client driver, PSv2, Credential Guard,
              DEP OptIn, Kerberos enc-types.
    ================================================================
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath    = '',
    [switch]$NonInteractive,
    [switch]$SkipAuditPolicy
)

# StrictMode OFF: with SilentlyContinue this combination otherwise produces
# silently-failed reads (null property access throws under Strict).
Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

$global:StartTime = Get-Date
$global:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:OK        = 0
$global:Failed    = 0
$global:Skipped   = 0

$_stamp = $global:StartTime.ToString('yyyyMMdd_HHmmss')
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "ZavetSecDefaults_$_stamp.html"
}

# -------------------------------------------------------
# Console helpers
# -------------------------------------------------------
function Write-Phase { param([string]$T)
    Write-Host ''
    Write-Host "  [>>] $T" -ForegroundColor Cyan
}
function Write-OK   { param([string]$M); Write-Host "  [OK] $M" -ForegroundColor Green }
function Write-Fail { param([string]$M); Write-Host "  [!!] $M" -ForegroundColor Yellow }
function Write-Err  { param([string]$M); Write-Host "  [XX] $M" -ForegroundColor Red }
function Write-Info { param([string]$M); Write-Host "  [..] $M" -ForegroundColor DarkGray }

# -------------------------------------------------------
# Core helpers
# -------------------------------------------------------
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { $null = New-Item -Path $Path -Force }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -EA SilentlyContinue
    }
}

function Remove-RegKey {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -EA SilentlyContinue
    }
}

function Add-Result {
    param([string]$Category, [string]$Name, [string]$Status, [string]$Note = '', [string]$ID = '')
    $global:Results.Add([PSCustomObject]@{
        ID       = $ID
        Category = $Category
        Name     = $Name
        Status   = $Status
        Note     = $Note
    })
    if ($Status -eq 'OK')      { $global:OK++;      Write-OK   "$Name" }
    elseif ($Status -eq 'SKIP'){ $global:Skipped++; Write-Info "$Name - $Note" }
    else                       { $global:Failed++;  Write-Err  "$Name - $Note" }
}

function Reset-Registry {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path,
        [string]$RegName,
        [string]$Action = 'Remove',   # Remove | SetValue
        $Value  = $null,
        [string]$Type   = 'DWord',
        [string]$ID     = ''
    )
    try {
        if ($Action -eq 'Remove') {
            Remove-RegValue $Path $RegName
        } else {
            Set-RegValue $Path $RegName $Value $Type
        }
        Add-Result $Category $Name 'OK' '' $ID
    } catch {
        Add-Result $Category $Name 'FAIL' $_.Exception.Message $ID
    }
}

# -------------------------------------------------------
# BANNER + HEADER
# -------------------------------------------------------
Write-Host ''
Write-Host '     ____                  _    ____            ' -ForegroundColor DarkCyan
Write-Host '    |_  /__ ___ _____ ___ | |_ / __/__ ___     ' -ForegroundColor Cyan
Write-Host '     / // _` \ V / -_)  _||  _\__ \/ -_) _|    ' -ForegroundColor Cyan
Write-Host '    /___\__,_|\_/\___\__| |_| |___/\___\__|    ' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '    ZavetSecWindowsDefaults v1.3                ' -ForegroundColor White
Write-Host '    Reset hardening to Windows defaults         ' -ForegroundColor DarkGray
Write-Host '    https://github.com/zavetsec                 ' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '    Script : ZavetSecWindowsDefaults v1.3'        -ForegroundColor Cyan
Write-Host "    Host   : $env:COMPUTERNAME"                   -ForegroundColor Gray
Write-Host "    Time   : $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host '  ============================================================' -ForegroundColor DarkCyan

# -------------------------------------------------------
# ADMIN CHECK
# -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err 'Not running as Administrator. Elevation required.'
    if (-not $NonInteractive) {
        Write-Host '  Press ENTER to exit...' -ForegroundColor DarkGray
        $null = [Console]::ReadLine()
    }
    exit 1
}

# -------------------------------------------------------
# CONFIRMATION
# -------------------------------------------------------
Write-Host ''
Write-Host '  [!!] WARNING: This will REMOVE hardening settings.' -ForegroundColor Yellow
Write-Host '       Use only when the JSON backup is lost or unavailable.' -ForegroundColor Yellow
Write-Host '       Prefer ZavetSec-Harden -Mode Rollback when possible.' -ForegroundColor DarkGray
Write-Host ''

if ($NonInteractive) {
    Write-Info '[-NonInteractive] Proceeding without confirmation.'
} else {
    $confirm = Read-Host '  Type YES to continue'
    if ($confirm -notmatch '^YES$') {
        Write-Host '  Aborted.' -ForegroundColor Red
        exit 0
    }
}

# ===========================================================
# SECTION 1: NETWORK - RESTORE DEFAULTS  (NET-001..NET-014)
# ===========================================================
Write-Phase 'NETWORK - restoring defaults'

# NET-001: LLMNR - remove policy key (default = enabled)
Reset-Registry 'Network' 'Re-enable LLMNR' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'Remove' -ID 'NET-001'

# NET-002: mDNS - remove policy key (default = enabled)
Reset-Registry 'Network' 'Re-enable mDNS' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 'Remove' -ID 'NET-002'

# NET-003: WPAD - remove DisableWpad (default = auto-detect enabled)
Reset-Registry 'Network' 'Re-enable WPAD auto-detection' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 'Remove' -ID 'NET-003'
try {
    # Restore WinHTTP Web Proxy Auto-Discovery Service to default Manual+started.
    $svc = Get-Service 'WinHttpAutoProxySvc' -EA SilentlyContinue
    if ($svc) {
        Set-Service 'WinHttpAutoProxySvc' -StartupType Manual -EA SilentlyContinue
        Start-Service 'WinHttpAutoProxySvc' -EA SilentlyContinue
    }
    Add-Result 'Network' 'Restore WinHttpAutoProxySvc to Manual' 'OK' '' 'NET-003'
} catch {
    Add-Result 'Network' 'Restore WinHttpAutoProxySvc to Manual' 'FAIL' $_.Exception.Message 'NET-003'
}

# NET-004: SMBv1 server - restore to default (enabled). Setting SMB1=1 is the
# legacy registry-driven enable; on modern Windows the actual driver state is
# governed by Windows-Optional-Feature SMB1Protocol. We re-enable both.
Reset-Registry 'Network' 'Restore SMBv1 server registry key' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 'SetValue' -Value 1 -ID 'NET-004'
# SMBv1 client driver - set back to manual load (3), reboot required
Reset-Registry 'Network' 'Restore SMBv1 client driver Start=3 (reboot required)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 'SetValue' -Value 3 -ID 'NET-004'
try {
    # Best-effort attempt to re-enable the optional feature too. Will report
    # EnablePending until reboot. On Server SKUs without the package it's a
    # no-op; SilentlyContinue keeps it quiet.
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -EA SilentlyContinue
    if ($f -and $f.State -eq 'Disabled') {
        Enable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -EA SilentlyContinue | Out-Null
        Add-Result 'Network' 'Re-enable SMB1Protocol optional feature (reboot required)' 'OK' '' 'NET-004'
    } else {
        Add-Result 'Network' 'SMB1Protocol optional feature already enabled or absent' 'SKIP' 'no action' 'NET-004'
    }
} catch {
    Add-Result 'Network' 'Re-enable SMB1Protocol optional feature' 'FAIL' $_.Exception.Message 'NET-004'
}

# NET-005: SMB signing server - remove requirements (default = not required)
Reset-Registry 'Network' 'Remove SMB signing requirement (server)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 'SetValue' -Value 0 -ID 'NET-005'
Reset-Registry 'Network' 'Remove SMB signing enable (server)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 'SetValue' -Value 0 -ID 'NET-005'

# NET-006: SMB signing client - remove requirement
Reset-Registry 'Network' 'Remove SMB signing requirement (client)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 'SetValue' -Value 0 -ID 'NET-006'

# NET-007: NetBIOS over TCP/IP - restore to default (0 = use DHCP setting) on every adapter
try {
    $adapterCount = 0
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA Stop | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 0 -Force -EA SilentlyContinue
        $adapterCount++
    }
    Add-Result 'Network' "Restore NetBIOS over TCP/IP on $adapterCount adapter(s)" 'OK' '' 'NET-007'
} catch {
    Add-Result 'Network' 'Restore NetBIOS over TCP/IP (all adapters)' 'FAIL' $_.Exception.Message 'NET-007'
}

# NET-008: LMHOSTS - restore to enabled (1 = Windows default)
Reset-Registry 'Network' 'Re-enable LMHOSTS lookup' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'EnableLMHOSTS' 'SetValue' -Value 1 -ID 'NET-008'

# NET-009: Anonymous SAM/Anonymous enumeration - restore defaults
Reset-Registry 'Network' 'Restore anonymous SAM enumeration to default' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 'SetValue' -Value 0 -ID 'NET-009'
Reset-Registry 'Network' 'Restore anonymous enumeration to default' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 'SetValue' -Value 0 -ID 'NET-009'

# NET-010: Remote Registry - restore to Manual (Windows default), stopped
try {
    $svc = Get-Service 'RemoteRegistry' -EA SilentlyContinue
    if ($svc) {
        Set-Service 'RemoteRegistry' -StartupType Manual -EA SilentlyContinue
        Add-Result 'Network' 'Restore Remote Registry to Manual (stopped)' 'OK' '' 'NET-010'
    } else {
        Add-Result 'Network' 'Remote Registry service' 'SKIP' 'service absent on this SKU' 'NET-010'
    }
} catch {
    Add-Result 'Network' 'Restore Remote Registry to Manual (stopped)' 'FAIL' $_.Exception.Message 'NET-010'
}

# NET-011: EveryoneIncludesAnonymous - restore default (0)
Reset-Registry 'Network' 'Restore Everyone includes Anonymous to default' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 'SetValue' -Value 0 -ID 'NET-011'

# NET-012: NullSessionPipes / NullSessionShares - restore defaults
# Windows default for NullSessionPipes on Server SKUs typically includes
# netlogon, samr, lsarpc. We restore to a reasonable empty default and let
# domain GPO re-populate if needed.
Reset-Registry 'Network' 'Reset NullSessionPipes (LanmanServer)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionPipes' 'Remove' -ID 'NET-012'
Reset-Registry 'Network' 'Reset NullSessionShares (LanmanServer)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares' 'Remove' -ID 'NET-012'
Reset-Registry 'Network' 'Reset RestrictNullSessAccess to default (1)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' 'SetValue' -Value 1 -ID 'NET-012'

# NET-013: DisableIPSourceRouting - remove explicit override (Windows default = 1)
Reset-Registry 'Network' 'Remove DisableIPSourceRouting override (IPv4)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 'Remove' -ID 'NET-013'
Reset-Registry 'Network' 'Remove DisableIPSourceRouting override (IPv6)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 'Remove' -ID 'NET-013'

# NET-014: EnableICMPRedirect - remove override (Windows default = 1, accept redirects)
Reset-Registry 'Network' 'Remove EnableICMPRedirect override' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 'Remove' -ID 'NET-014'

# ===========================================================
# SECTION 2: CREDENTIALS - RESTORE DEFAULTS  (CRED-001..CRED-011)
# ===========================================================
Write-Phase 'CREDENTIALS - restoring defaults'

# CRED-001: WDigest - remove override
Reset-Registry 'Credentials' 'Remove WDigest UseLogonCredential override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 'Remove' -ID 'CRED-001'

# CRED-002: LSA RunAsPPL - remove (default = not set)
Reset-Registry 'Credentials' 'Remove LSA RunAsPPL' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 'Remove' -ID 'CRED-002'
Reset-Registry 'Credentials' 'Remove LSA RunAsPPLBoot (Win10 1903+)' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPLBoot' 'Remove' -ID 'CRED-002'

# CRED-003: Credential Guard - remove ALL policy keys
try {
    Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags'
    $dgKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    @('EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures',
      'HypervisorEnforcedCodeIntegrity','HVCIMATRequired','LsaCfgFlags') | ForEach-Object {
        Remove-RegValue $dgKey $_
    }
    Add-Result 'Credentials' 'Remove Credential Guard / VBS policy keys' 'OK' '(reboot required)' 'CRED-003'
} catch {
    Add-Result 'Credentials' 'Remove Credential Guard / VBS policy keys' 'FAIL' $_.Exception.Message 'CRED-003'
}

# CRED-004: LmCompatibilityLevel - Windows default = 3
Reset-Registry 'Credentials' 'Restore LmCompatibilityLevel to 3 (Windows default)' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 'SetValue' -Value 3 -ID 'CRED-004'

# CRED-005: NoLMHash - remove explicit override (Windows default in Vista+ already does not store LM hashes)
Reset-Registry 'Credentials' 'Remove NoLMHash override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 'Remove' -ID 'CRED-005'

# CRED-006: NTLM min session security - remove overrides
Reset-Registry 'Credentials' 'Remove NTLMMinServerSec override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' 'Remove' -ID 'CRED-006'
Reset-Registry 'Credentials' 'Remove NTLMMinClientSec override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 'Remove' -ID 'CRED-006'

# CRED-007: DisableDomainCreds - remove (default = 0, allow saving creds)
Reset-Registry 'Credentials' 'Remove DisableDomainCreds override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableDomainCreds' 'Remove' -ID 'CRED-007'

# CRED-008: CredSSP / AllowEncryptionOracle - remove the policy key entirely.
# This is the setting whose strict value (0) breaks RDP when the other end is
# unpatched. Removing it returns the OS to its safe-by-default Mitigated (=2)
# behaviour without leaving any registry override behind.
try {
    Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'AllowEncryptionOracle'
    # Also remove the parent key if it ended up empty -- avoids leaving stale GPO scaffold.
    $kParent = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
    if (Test-Path $kParent) {
        $remaining = Get-Item $kParent -EA SilentlyContinue
        $valCount = if ($remaining) { @($remaining.Property).Count } else { 0 }
        $subCount = @(Get-ChildItem $kParent -EA SilentlyContinue).Count
        if ($valCount -eq 0 -and $subCount -eq 0) { Remove-Item $kParent -Force -EA SilentlyContinue }
    }
    Add-Result 'Credentials' 'Remove CredSSP AllowEncryptionOracle (RDP fix)' 'OK' 'restart TermService or reboot' 'CRED-008'
} catch {
    Add-Result 'Credentials' 'Remove CredSSP AllowEncryptionOracle' 'FAIL' $_.Exception.Message 'CRED-008'
}

# CRED-009: Kerberos SupportedEncryptionTypes - remove override
# Windows default behaviour: client and DC negotiate based on
# msDS-SupportedEncryptionTypes attributes; removing the local registry override
# returns the host to the OS-default supported set (RC4 + AES on legacy, AES on modern).
Reset-Registry 'Credentials' 'Remove Kerberos SupportedEncryptionTypes override (reboot required)' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 'Remove' -ID 'CRED-009'

# CRED-010: Remote Credential Guard / AllowProtectedCreds - remove
Reset-Registry 'Credentials' 'Remove Remote Credential Guard policy' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' 'Remove' -ID 'CRED-010'

# CRED-011: Netlogon hardening - remove ZeroLogon-era hardening keys
$netlogonP = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
Reset-Registry 'Credentials' 'Remove Netlogon RequireSignOrSeal override' `
    $netlogonP 'RequireSignOrSeal' 'Remove' -ID 'CRED-011'
Reset-Registry 'Credentials' 'Remove Netlogon SealSecureChannel override' `
    $netlogonP 'SealSecureChannel' 'Remove' -ID 'CRED-011'
Reset-Registry 'Credentials' 'Remove Netlogon SignSecureChannel override' `
    $netlogonP 'SignSecureChannel' 'Remove' -ID 'CRED-011'
Reset-Registry 'Credentials' 'Remove Netlogon RequireStrongKey override' `
    $netlogonP 'RequireStrongKey' 'Remove' -ID 'CRED-011'
Reset-Registry 'Credentials' 'Remove Netlogon DisablePasswordChange override' `
    $netlogonP 'DisablePasswordChange' 'Remove' -ID 'CRED-011'

# ===========================================================
# SECTION 3: POWERSHELL - RESTORE DEFAULTS  (PS-001..PS-005)
# ===========================================================
Write-Phase 'POWERSHELL - restoring defaults'

# PS-001: Script Block Logging - disable
Reset-Registry 'PowerShell' 'Disable Script Block Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'SetValue' -Value 0 -ID 'PS-001'
Reset-Registry 'PowerShell' 'Disable Script Block Invocation Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockInvocationLogging' 'SetValue' -Value 0 -ID 'PS-001'

# PS-002: Module Logging - disable + remove ModuleNames key
Reset-Registry 'PowerShell' 'Disable Module Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 'SetValue' -Value 0 -ID 'PS-002'
try {
    Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    Add-Result 'PowerShell' 'Remove ModuleNames wildcard key' 'OK' '' 'PS-002'
} catch {
    Add-Result 'PowerShell' 'Remove ModuleNames wildcard key' 'FAIL' $_.Exception.Message 'PS-002'
}

# PS-003: Transcription - disable
Reset-Registry 'PowerShell' 'Disable Transcription' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 'SetValue' -Value 0 -ID 'PS-003'
Reset-Registry 'PowerShell' 'Remove Transcription invocation header flag' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' 'Remove' -ID 'PS-003'
Reset-Registry 'PowerShell' 'Remove Transcription OutputDirectory' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' 'Remove' -ID 'PS-003'

# PS-004: PSv2 - re-enable (requires reboot)
try {
    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -EA SilentlyContinue | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2'     -NoRestart -EA SilentlyContinue | Out-Null
    Add-Result 'PowerShell' 'Re-enable PowerShell v2 feature' 'OK' '(reboot required)' 'PS-004'
} catch {
    Add-Result 'PowerShell' 'Re-enable PowerShell v2 feature' 'FAIL' $_.Exception.Message 'PS-004'
}

# PS-005: Execution Policy - remove machine-level override
Reset-Registry 'PowerShell' 'Remove Machine ExecutionPolicy override' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' 'Remove' -ID 'PS-005'
Reset-Registry 'PowerShell' 'Remove Machine EnableScripts override' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'EnableScripts' 'Remove' -ID 'PS-005'

# ===========================================================
# SECTION 4: AUDIT POLICY - RESET ALL TO NO AUDITING  (AUD-001..AUD-029)
# ===========================================================
if (-not $SkipAuditPolicy) {
    Write-Phase 'AUDIT POLICY - resetting all subcategories to No Auditing'

    $auditSubcats = @(
        @{ ID='AUD-001'; Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Sub='Process Creation' }
        @{ ID='AUD-002'; Guid='{0CCE9223-69AE-11D9-BED3-505054503030}'; Sub='Process Termination' }
        @{ ID='AUD-003'; Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Sub='Logon' }
        @{ ID='AUD-004'; Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Sub='Logoff' }
        @{ ID='AUD-005'; Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Sub='Account Lockout' }
        @{ ID='AUD-006'; Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Sub='Special Logon' }
        @{ ID='AUD-007'; Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Authentication Service' }
        @{ ID='AUD-008'; Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Service Ticket Ops' }
        @{ ID='AUD-009'; Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Sub='Credential Validation' }
        @{ ID='AUD-010'; Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Sub='User Account Management' }
        @{ ID='AUD-011'; Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Sub='Security Group Management' }
        @{ ID='AUD-012'; Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Sub='Audit Policy Change' }
        @{ ID='AUD-013'; Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Sub='Authentication Policy Change' }
        @{ ID='AUD-014'; Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Sub='System Integrity' }
        @{ ID='AUD-015'; Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Sub='Security System Extension' }
        @{ ID='AUD-016'; Guid='{0CCE921D-69AE-11D9-BED3-505054503030}'; Sub='File System' }
        @{ ID='AUD-017'; Guid='{0CCE921E-69AE-11D9-BED3-505054503030}'; Sub='Registry' }
        @{ ID='AUD-018'; Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Sub='Sensitive Privilege Use' }
        @{ ID='AUD-019'; Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Sub='Other Object Access Events' }
        @{ ID='AUD-020'; Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Sub='Removable Storage' }
        @{ ID='AUD-021'; Guid='{0CCE922D-69AE-11D9-BED3-505054503030}'; Sub='DPAPI Activity' }
        @{ ID='AUD-022'; Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Sub='RPC Events' }
        @{ ID='AUD-023'; Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Sub='Security State Change' }
        @{ ID='AUD-024'; Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; Sub='Other System Events' }
        @{ ID='AUD-025'; Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Sub='Filtering Platform Connection' }
        @{ ID='AUD-026'; Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; Sub='Detailed File Share' }
        @{ ID='AUD-027'; Guid='{0CCE9243-69AE-11D9-BED3-505054503030}'; Sub='Network Policy Server' }
    )

    $ap = "$env:SystemRoot\System32\auditpol.exe"
    foreach ($ac in $auditSubcats) {
        try {
            $null = & $ap /set /subcategory:"$($ac.Guid)" /success:disable /failure:disable 2>&1
            if ($LASTEXITCODE -eq 0) {
                Add-Result 'AuditPolicy' "Reset: $($ac.Sub)" 'OK' '' $ac.ID
            } else {
                Add-Result 'AuditPolicy' "Reset: $($ac.Sub)" 'FAIL' "auditpol exit $LASTEXITCODE" $ac.ID
            }
        } catch {
            Add-Result 'AuditPolicy' "Reset: $($ac.Sub)" 'FAIL' $_.Exception.Message $ac.ID
        }
    }

    # AUD-028: ProcessCreationIncludeCmdLine - remove
    Reset-Registry 'AuditPolicy' 'Remove ProcessCreationIncludeCmdLine_Enabled' `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 'Remove' -ID 'AUD-028'

    # AUD-029: SCENoApplyLegacyAuditPolicy - remove
    Reset-Registry 'AuditPolicy' 'Remove SCENoApplyLegacyAuditPolicy override' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 'Remove' -ID 'AUD-029'
} else {
    Write-Phase 'AUDIT POLICY - skipped (-SkipAuditPolicy)'
    Add-Result 'AuditPolicy' 'Audit policy reset skipped (-SkipAuditPolicy flag)' 'SKIP' 'managed via GPO' ''
}

# ===========================================================
# SECTION 5: SYSTEM - RESTORE DEFAULTS  (SYS-001..SYS-015)
# ===========================================================
Write-Phase 'SYSTEM - restoring defaults'

# SYS-001: UAC - restore to Windows defaults
try {
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue $uacKey 'ConsentPromptBehaviorAdmin' 5   # Default: prompt for consent (non-binaries)
    Set-RegValue $uacKey 'ConsentPromptBehaviorUser'  3   # Default: prompt for creds
    Set-RegValue $uacKey 'PromptOnSecureDesktop'      1   # Default: secure desktop on
    Set-RegValue $uacKey 'EnableLUA'                  1   # Default: UAC on
    Add-Result 'System' 'Restore UAC to Windows defaults' 'OK' '' 'SYS-001'
} catch {
    Add-Result 'System' 'Restore UAC to Windows defaults' 'FAIL' $_.Exception.Message 'SYS-001'
}

# SYS-002: AutoRun / AutoPlay - restore defaults
Reset-Registry 'System' 'Restore NoDriveTypeAutoRun to default (145)' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 'SetValue' -Value 145 -ID 'SYS-002'
Reset-Registry 'System' 'Remove NoAutorun override' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 'Remove' -ID 'SYS-002'
Reset-Registry 'System' 'Remove HKCU NoAutorun override' `
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 'Remove' -ID 'SYS-002'
Reset-Registry 'System' 'Remove NoAutoplayfornonVolume override' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 'Remove' -ID 'SYS-002'

# SYS-003: RDP NLA - remove explicit override (Windows default already requires NLA on Server 2012+)
Reset-Registry 'System' 'Remove RDP NLA UserAuthentication override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 'Remove' -ID 'SYS-003'
Reset-Registry 'System' 'Remove RDP NLA UserAuthenticationRequired override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthenticationRequired' 'Remove' -ID 'SYS-003'
Reset-Registry 'System' 'Remove RDP SecurityLayer override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer' 'Remove' -ID 'SYS-003'

# SYS-004: RDP encryption - restore to Windows default (2 = Client Compatible)
Reset-Registry 'System' 'Restore RDP MinEncryptionLevel to 2 (Client Compatible)' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' 'SetValue' -Value 2 -ID 'SYS-004'

# SYS-005: DEP - restore to OptIn (Windows default)
try {
    & bcdedit /set '{current}' nx OptIn 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Add-Result 'System' 'Restore DEP to OptIn (reboot required)' 'OK' '' 'SYS-005'
    } else {
        Add-Result 'System' 'Restore DEP to OptIn' 'FAIL' "bcdedit exit $LASTEXITCODE" 'SYS-005'
    }
} catch {
    Add-Result 'System' 'Restore DEP to OptIn' 'FAIL' $_.Exception.Message 'SYS-005'
}

# SYS-006: Event Log - restore Windows defaults: 20 MB size, overwrite-when-full,
# no archive. Also clear Retention/AutoBackupLogFiles overrides we may have set.
try {
    & wevtutil sl Security    /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null
    & wevtutil sl System      /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null
    & wevtutil sl Application /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'MaxSize' 20971520
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'MaxSize' 20971520
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'MaxSize' 20971520
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'Retention' 0
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'Retention' 0
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'Retention' 0
    Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'AutoBackupLogFiles'
    Add-Result 'System' 'Restore Event Log sizes to 20 MB (Windows default)' 'OK' '' 'SYS-006'
} catch {
    Add-Result 'System' 'Restore Event Log sizes' 'FAIL' $_.Exception.Message 'SYS-006'
}

# SYS-007: DoH - remove policy
Reset-Registry 'System' 'Remove DNS over HTTPS policy' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 'Remove' -ID 'SYS-007'

# SYS-008: Print Spooler - restore Windows default. On most SKUs default is Automatic+Started.
# The harden script disables it only on PrintServer-non-print profile, so a defaults reset
# should bring it back to Automatic+Running (it is the only safe choice for unknown roles).
try {
    $svc = Get-Service 'Spooler' -EA SilentlyContinue
    if ($svc) {
        Set-Service 'Spooler' -StartupType Automatic -EA SilentlyContinue
        Start-Service 'Spooler' -EA SilentlyContinue
        Add-Result 'System' 'Re-enable Print Spooler (Automatic + started)' 'OK' '' 'SYS-008'
    } else {
        Add-Result 'System' 'Print Spooler service' 'SKIP' 'service absent on this SKU' 'SYS-008'
    }
} catch {
    Add-Result 'System' 'Re-enable Print Spooler' 'FAIL' $_.Exception.Message 'SYS-008'
}

# SYS-009: DNS Client multicast - re-enable (default = Automatic+started)
try {
    $svc = Get-Service 'Dnscache' -EA SilentlyContinue
    if ($svc) {
        Set-Service 'Dnscache' -StartupType Automatic -EA SilentlyContinue
        Start-Service 'Dnscache' -EA SilentlyContinue
    }
    # Multicast policy keys removed (NET-001/NET-002 already covered the policy keys)
    Add-Result 'System' 'Restore DNS Client service to Automatic' 'OK' '' 'SYS-009'
} catch {
    Add-Result 'System' 'Restore DNS Client service' 'FAIL' $_.Exception.Message 'SYS-009'
}

# SYS-010: LSASS PPL audit / additional LSASS hardening - remove extras
# (RunAsPPL itself is handled by CRED-002; here we clean any audit-mode key.)
Reset-Registry 'System' 'Remove LSASS audit-mode flag' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'AuditLevel' 'Remove' -ID 'SYS-010'

# SYS-013: Wintrust EnableCertPaddingCheck (Flame mitigation) - remove explicit override
# Windows defaults vary by patch level; removing leaves OS-managed default.
Reset-Registry 'System' 'Remove Wintrust EnableCertPaddingCheck (x64)' `
    'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck' 'Remove' -ID 'SYS-013'
Reset-Registry 'System' 'Remove Wintrust EnableCertPaddingCheck (Wow6432Node)' `
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck' 'Remove' -ID 'SYS-013'

# SYS-014: NTLM audit policy (AuditReceivingNTLMTraffic / RestrictReceivingNTLMTraffic) - remove
$lsaMSV = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
Reset-Registry 'System' 'Remove NTLM AuditReceivingNTLMTraffic' `
    $lsaMSV 'AuditReceivingNTLMTraffic' 'Remove' -ID 'SYS-014'
Reset-Registry 'System' 'Remove NTLM RestrictReceivingNTLMTraffic' `
    $lsaMSV 'RestrictReceivingNTLMTraffic' 'Remove' -ID 'SYS-014'
Reset-Registry 'System' 'Remove NTLM RestrictSendingNTLMTraffic' `
    $lsaMSV 'RestrictSendingNTLMTraffic' 'Remove' -ID 'SYS-014'

# SYS-015: NULL session fallback for LocalSystem - remove restriction
Reset-Registry 'System' 'Remove allownullsessionfallback restriction' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback' 'Remove' -ID 'SYS-015'

# ===========================================================
# SECTION 6: GENERATE REPORT
# ===========================================================
Write-Phase 'Generating report'

$duration      = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")
$totalCount    = $global:Results.Count
$okCount       = $global:OK
$failCount     = $global:Failed
$skipCount     = $global:Skipped

# HTML-encoded variables for safe interpolation
$_compNameEnc   = [System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)
$_outputPathEnc = [System.Net.WebUtility]::HtmlEncode($OutputPath)

# Category summary
$catGroups = $global:Results | Group-Object Category
$catRows = foreach ($g in $catGroups) {
    $gOK   = ($g.Group | Where-Object { $_.Status -eq 'OK'   }).Count
    $gFail = ($g.Group | Where-Object { $_.Status -eq 'FAIL' }).Count
    $gSkip = ($g.Group | Where-Object { $_.Status -eq 'SKIP' }).Count
    "<tr><td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px'>$($g.Name)</td><td style='font-family:JetBrains Mono,monospace;color:#00ff88'>$gOK</td><td style='font-family:JetBrains Mono,monospace;color:#ff2d55'>$gFail</td><td style='font-family:JetBrains Mono,monospace;color:#8b949e'>$gSkip</td></tr>"
}
$catRows = $catRows -join "`n"

# Result rows -- include ID column
$tableRows = foreach ($r in $global:Results) {
    $sc = switch ($r.Status) {
        'OK'   { '#00ff88' }
        'FAIL' { '#ff2d55' }
        default{ '#ffd60a' }
    }
    $idEnc   = [System.Net.WebUtility]::HtmlEncode($r.ID)
    $catEnc  = [System.Net.WebUtility]::HtmlEncode($r.Category)
    $nameEnc = [System.Net.WebUtility]::HtmlEncode($r.Name)
    $noteEnc = [System.Net.WebUtility]::HtmlEncode($r.Note)
    "<tr>
      <td style='font-family:JetBrains Mono,monospace;color:#8b949e;font-size:10px;white-space:nowrap'>$idEnc</td>
      <td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px;white-space:nowrap'>$catEnc</td>
      <td style='font-size:12px'>$nameEnc</td>
      <td><span style='font-family:JetBrains Mono,monospace;color:$sc;font-weight:700;font-size:11px'>$($r.Status)</span></td>
      <td style='color:#c9d1d9;font-size:11px'>$noteEnc</td>
    </tr>"
}
$tableRows = $tableRows -join "`n"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZavetSec Windows Defaults Reset // $_compNameEnc</title>
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
  position:fixed;top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,0.015) 2px,rgba(0,255,136,0.015) 4px);
  pointer-events:none;z-index:0;
}
body::after{
  content:'';
  position:fixed;top:0;left:0;right:0;bottom:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(0,255,136,0.06) 0%,transparent 65%);
  pointer-events:none;z-index:0;
}
.wrap{position:relative;z-index:1}
header{
  background:linear-gradient(180deg,#0d1117 0%,#0a0d10 100%);
  border-bottom:1px solid rgba(0,255,136,0.18);
  padding:22px 40px;
  display:flex;align-items:center;gap:24px;
}
.logo-block{display:flex;flex-direction:column;gap:2px}
.logo-name{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;font-weight:700;
  color:#00ff88;letter-spacing:3px;text-transform:uppercase;
}
.logo-title{
  font-family:'Share Tech Mono',monospace;
  font-size:22px;font-weight:400;
  color:#e6edf3;letter-spacing:2px;
}
.logo-title span{color:#00ff88}
.logo-cursor{
  color:#00ff88;
  animation:cur 1s step-end infinite;
}
@keyframes cur{0%,100%{opacity:1}50%{opacity:0}}
.header-meta{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;color:#8b949e;margin-top:4px;
}
.header-right{
  margin-left:auto;text-align:right;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;color:#8b949e;line-height:1.9;
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
.main{padding:28px 40px;max-width:1400px;margin:0 auto}

/* SECTION HEADER */
.sec-hdr{
  display:flex;align-items:center;gap:10px;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:700;
  color:#00ff88;text-transform:uppercase;letter-spacing:2px;
  margin-bottom:14px;margin-top:28px;
  padding-bottom:7px;
  border-bottom:1px solid rgba(0,255,136,0.15);
}
.sec-num{
  background:rgba(0,255,136,0.1);
  border:1px solid rgba(0,255,136,0.3);
  color:#00ff88;padding:1px 7px;border-radius:3px;font-size:9px;
}

/* ALERT BOX */
.alert-warn{
  background:rgba(255,107,0,0.08);
  border:1px solid rgba(255,107,0,0.4);
  border-left:3px solid #ff6b00;
  border-radius:6px;
  padding:12px 18px;
  margin-bottom:20px;
  font-family:'JetBrains Mono',monospace;
  font-size:11px;color:#ff6b00;
  line-height:1.8;
}
.alert-warn .warn-title{
  font-size:12px;font-weight:700;
  letter-spacing:1px;margin-bottom:4px;
}

/* STAT CARDS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.sc{
  background:#0d1117;
  border:1px solid #21262d;
  border-radius:8px;
  padding:14px 12px;
  position:relative;overflow:hidden;
  transition:border-color .2s;
}
.sc:hover{border-color:rgba(0,255,136,0.25)}
.sc::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,255,136,0.25),transparent);
}
.sc .n{
  font-family:'JetBrains Mono',monospace;
  font-size:28px;font-weight:700;line-height:1.1;
}
.sc .l{
  font-family:'Rajdhani',sans-serif;
  font-size:9px;color:#8b949e;
  text-transform:uppercase;letter-spacing:1px;
  margin-top:4px;font-weight:600;
}

/* GRID + PANEL */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.panel{
  background:#0d1117;border:1px solid #21262d;
  border-radius:8px;padding:14px 18px;
}
.panel-title{
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;color:#8b949e;
  text-transform:uppercase;letter-spacing:1.5px;
  margin-bottom:10px;padding-bottom:6px;
  border-bottom:1px solid #21262d;
}

/* TABLES */
table{
  width:100%;border-collapse:collapse;
  background:#0d1117;border-radius:8px;
  overflow:hidden;border:1px solid #21262d;font-size:12px;
}
.tbl{width:100%;border-collapse:collapse;font-size:11px}
th{
  background:#010409;color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:9px;text-transform:uppercase;letter-spacing:1.2px;
  padding:9px 10px;text-align:left;font-weight:700;white-space:nowrap;
  border-bottom:1px solid rgba(0,255,136,0.1);
}
td{
  padding:8px 10px;border-top:1px solid #21262d;
  vertical-align:top;font-family:'Rajdhani',sans-serif;
}
tr:hover td{background:#0a0d10;transition:background .15s}

/* NEXT STEPS */
.step{
  display:flex;align-items:flex-start;gap:12px;
  padding:8px 0;border-bottom:1px solid #21262d;
}
.step:last-child{border-bottom:none}
.step-num{
  font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:700;
  color:#00ff88;
  background:rgba(0,255,136,0.08);
  border:1px solid rgba(0,255,136,0.2);
  border-radius:3px;padding:1px 6px;
  white-space:nowrap;flex-shrink:0;margin-top:2px;
}
.step-text{
  font-family:'Rajdhani',sans-serif;
  font-size:12px;color:#c9d1d9;
}
.step-text .hl{
  font-family:'JetBrains Mono',monospace;
  color:#00ff88;font-size:10px;
}

/* FOOTER */
footer{
  margin-top:40px;padding:16px 40px;
  border-top:1px solid rgba(0,255,136,0.1);
  color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;text-align:center;letter-spacing:.5px;
}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo-block">
    <div class="logo-name">ZavetSec<div class="dot-anim" style="display:inline-flex"><span></span><span></span><span></span></div></div>
    <div class="logo-title">Windows<span>Defaults</span><span class="logo-cursor">_</span> <span style="font-size:13px;color:#8b949e;font-weight:400">v1.3</span></div>
    <div class="header-meta">Reset to Windows Defaults &nbsp;//&nbsp; Host: $_compNameEnc &nbsp;//&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;//&nbsp; Duration: $duration</div>
  </div>
  <div class="header-right">
    <div class="brand">ZavetSec</div>
    <div>github.com/zavetsec</div>
    <div>Companion to ZavetSec-Harden v1.3</div>
  </div>
</header>

<div class="main">

  <!-- SECTION 01: WARNING -->
  <div class="sec-hdr"><span class="sec-num">01</span> Status</div>

  <div class="alert-warn">
    <div class="warn-title">&#9888;&nbsp; HARDENING REMOVED</div>
    Security hardening settings have been reset to Windows out-of-box defaults on this machine.<br>
    Reboot required to finalize: &nbsp;<strong>SMBv1 client driver</strong> &nbsp;&bull;&nbsp; <strong>PSv2 re-enable</strong> &nbsp;&bull;&nbsp; <strong>DEP OptIn</strong> &nbsp;&bull;&nbsp; <strong>Credential Guard removal</strong> &nbsp;&bull;&nbsp; <strong>Kerberos enc-types</strong>
  </div>

  <!-- SECTION 02: STATS -->
  <div class="sec-hdr"><span class="sec-num">02</span> Summary</div>

  <div class="stats">
    <div class="sc"><div class="n" style="color:#e6edf3">$totalCount</div><div class="l">Total Actions</div></div>
    <div class="sc"><div class="n" style="color:#00ff88">$okCount</div><div class="l">Completed OK</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$failCount</div><div class="l">Failed</div></div>
    <div class="sc"><div class="n" style="color:#8b949e">$skipCount</div><div class="l">Skipped</div></div>
  </div>

  <!-- SECTION 03: BREAKDOWN + NEXT STEPS -->
  <div class="sec-hdr"><span class="sec-num">03</span> Category Breakdown &amp; Next Steps</div>

  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Results by Category</div>
      <table class="tbl">
        <thead><tr><th>Category</th><th style="color:#00ff88">OK</th><th style="color:#ff2d55">Failed</th><th style="color:#8b949e">Skipped</th></tr></thead>
        <tbody>$catRows</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Next Steps</div>
      <div style="padding:4px 0">
        <div class="step">
          <span class="step-num">01</span>
          <span class="step-text"><strong>Reboot</strong> to finalize SMBv1, PSv2, DEP, Credential Guard, Kerberos changes</span>
        </div>
        <div class="step">
          <span class="step-num">02</span>
          <span class="step-text">Verify RDP / SMB / domain authentication work as expected</span>
        </div>
        <div class="step">
          <span class="step-num">03</span>
          <span class="step-text">Re-run <span class="hl">ZavetSec-Harden -Mode Audit</span> to confirm clean baseline</span>
        </div>
        <div class="step">
          <span class="step-num">04</span>
          <span class="step-text">Re-apply hardening when ready: <span class="hl">ZavetSec-Harden -Mode Apply</span></span>
        </div>
      </div>
    </div>
  </div>

  <!-- SECTION 04: FULL LOG -->
  <div class="sec-hdr"><span class="sec-num">04</span> All Actions <span style="color:#8b949e;font-weight:400">($totalCount)</span></div>

  <table>
    <thead>
      <tr><th>ID</th><th>Category</th><th>Action</th><th>Status</th><th>Note</th></tr>
    </thead>
    <tbody>
      $tableRows
    </tbody>
  </table>

</div><!-- /main -->

<footer>
  <span style="color:#00ff88;font-weight:700;letter-spacing:2px">ZAVETSEC</span>
  &nbsp;&bull;&nbsp; ZavetSecWindowsDefaults v1.3
  &nbsp;&bull;&nbsp; github.com/zavetsec
  &nbsp;&bull;&nbsp; Host: $_compNameEnc
  &nbsp;&bull;&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  &nbsp;&bull;&nbsp; <span style="color:#ff6b00;font-weight:700">HARDENING REMOVED &mdash; REBOOT REQUIRED</span>
</footer>
</div><!-- /wrap -->
</body>
</html>
"@

$_outDir = Split-Path $OutputPath -Parent
if ($_outDir -and -not (Test-Path $_outDir)) {
    $null = New-Item -Path $_outDir -ItemType Directory -Force
}

try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  [OK] Report saved: $OutputPath" -ForegroundColor Green
} catch {
    $OutputPath = Join-Path $env:TEMP "ZavetSecDefaults_${env:COMPUTERNAME}_$_stamp.html"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "  [OK] Report saved to TEMP: $OutputPath" -ForegroundColor Yellow
}

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------
$sep = '-' * 64
Write-Host ''; Write-Host $sep -ForegroundColor DarkGray
Write-Host '  ZAVETSEC WINDOWS DEFAULTS COMPLETE  (v1.3)' -ForegroundColor White
Write-Host $sep -ForegroundColor DarkGray
Write-Host "  Host      : $env:COMPUTERNAME"       -ForegroundColor Gray
Write-Host "  Duration  : $duration"               -ForegroundColor Gray
Write-Host "  Total     : $totalCount actions"     -ForegroundColor Gray
Write-Host "  OK        : $okCount"                -ForegroundColor Green
Write-Host "  Failed    : $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Skipped   : $skipCount" -ForegroundColor DarkGray
Write-Host ''
Write-Host '  [!] Reboot required for:' -ForegroundColor Yellow
Write-Host '      SMBv1 client driver, PSv2, DEP OptIn, Credential Guard removal, Kerberos enc-types' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  [!] If RDP was broken: changes take effect after either reboot or:' -ForegroundColor Yellow
Write-Host '      Restart-Service TermService -Force' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Report: $OutputPath" -ForegroundColor Cyan
Write-Host $sep -ForegroundColor DarkGray

if (-not $NonInteractive) {
    Write-Host ''
    Write-Host '  Open HTML report in browser? [Y/N]: ' -ForegroundColor Yellow -NoNewline
    $open = [Console]::ReadLine()
    if ($open -match '^[Yy]') { Start-Process $OutputPath }
    Write-Host ''
    Write-Host '  Press ENTER to exit...' -ForegroundColor DarkGray
    $null = [Console]::ReadLine()
} else {
    Write-Host "  [-NonInteractive] Done. Report: $OutputPath" -ForegroundColor DarkGray
}
