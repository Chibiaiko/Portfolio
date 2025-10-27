<#
.SYNOPSIS
    Enable Advanced Audit Policy override for Windows 11 (STIG-compliant)

.NOTES
Author       : Alexis McGuire
LinkedIn     : linkedin.com/in/alexismcguire1/
GitHub       : github.com/Chibiaiko
Date Created : 2025-10-27
Last Modified: 2025-10-27
Version      : 1.0
CVEs         : N/A
Plugin IDs   : N/A
STIG-ID      : WN11-SO-000030

.TESTED ON
Date(s) Tested :
Tested By      :
Systems Tested :
PowerShell Ver.:

.USAGE
This script enables the Advanced Audit Policy override on Windows 11 systems to ensure STIG compliance.
Run as Administrator. Refreshes local group policy after applying the setting.

Example syntax:

PS C:\> .\Enable-AdvancedAuditPolicyOverride.ps1
#>

# --- Log file ---
$logFile = "C:\STIG_Logs\WN11_AuditPolicyOverride.txt"
if (!(Test-Path "C:\STIG_Logs")) { 
    New-Item -Path "C:\STIG_Logs" -ItemType Directory | Out-Null 
}

# --- Admin check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ ERROR: Script must be run as Administrator."
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - FAIL - Not run as Administrator."
    exit 1
}

Write-Host "`n=== STIG WN11 Advanced Audit Policy Override ===`n"

# --- Enable Advanced Audit Policy override ---
try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
                     -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force
    Write-Host "✅ Advanced Audit Policy override enabled."
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Advanced Audit Policy override enabled."
} catch {
    Write-Host "❌ Failed to set SCENoApplyLegacyAuditPolicy. $_"
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - FAIL - Cannot set SCENoApplyLegacyAuditPolicy."
    exit 1
}

# --- Force Local Group Policy refresh ---
try {
    Write-Host "🔄 Refreshing local group policy..."
    gpupdate /force | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "✅ Group Policy refreshed."
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Local Group Policy refreshed."
} catch {
    Write-Host "❌ Failed to refresh Group Policy. $_"
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - FAIL - Cannot refresh Group Policy."
}

# --- Verification ---
$registryCheck = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
                  -Name "SCENoApplyLegacyAuditPolicy").SCENoApplyLegacyAuditPolicy

if ($registryCheck -eq 1) {
    Write-Host "`n✅ PASS: Advanced Audit Policy override is ENABLED."
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - PASS: Advanced Audit Policy override is ENABLED."
} else {
    Write-Host "`n❌ FAIL: Advanced Audit Policy override is NOT enabled."
    Add-Content $logFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - FAIL: Advanced Audit Policy override is NOT enabled."
    exit 1
}
