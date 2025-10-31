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
    Date(s) Tested  : 2025-10-27
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    This script enables the Advanced Audit Policy override on Windows 11 systems to ensure STIG compliance.
    Run as Administrator. Refreshes local group policy after applying the setting.

Example syntax:

PS C:\> .\Enable-AdvancedAuditPolicyOverride.ps1
#>

<#
.SYNOPSIS
Checks and fixes the SCENoApplyLegacyAuditPolicy registry setting.

.DESCRIPTION
Ensures that the registry value:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy
exists and is set to 1 (Enabled). If not, the script will create or correct it.

#>

# Define registry key and value details
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"
$DesiredValue = 1

Write-Host "Checking registry value: $RegPath\$ValueName ..." -ForegroundColor Cyan

# Check if the registry key exists
if (-not (Test-Path $RegPath)) {
    Write-Host "Registry path does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $RegPath -Force | Out-Null
}

# Check if the value exists
try {
    $CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    Write-Host "Current value: $CurrentValue"
} catch {
    Write-Host "Registry value does not exist. Creating it..." -ForegroundColor Yellow
    $CurrentValue = $null
}

# Compare and fix if needed
if ($CurrentValue -ne $DesiredValue) {
    Write-Host "Updating registry value to $DesiredValue ..." -ForegroundColor Yellow
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -Type DWord
    Write-Host "Registry value updated successfully!" -ForegroundColor Green
} else {
    Write-Host "Registry value is already correctly configured." -ForegroundColor Green
}

# Verification step
$Verify = Get-ItemProperty -Path $RegPath -Name $ValueName | Select-Object -ExpandProperty $ValueName
Write-Host "Final configured value: $Verify"
if ($Verify -eq $DesiredValue) {
    Write-Host "✅ Configuration is correct." -ForegroundColor Green
} else {
    Write-Host "❌ Configuration is incorrect. Please check permissions or rerun as Administrator." -ForegroundColor Red
}
