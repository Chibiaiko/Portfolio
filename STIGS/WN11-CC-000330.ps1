
<#
.SYNOPSIS
Remediates and verifies that the WinRM Client 'AllowBasic' registry setting is set to 0 (disabled) in accordance with STIG requirements.

.NOTES
Author        : Alexis McGuire
LinkedIn      : linkedin.com/in/alexismcguire1/
GitHub        : github.com/Chibiaiko
Date Created  : 2025-10-28
Last Modified : 2025-10-28
Version       : 1.0
CVEs          : N/A
Plugin IDs    : N/A
STIG-ID       : WN11-CC-000330

.TESTED ON
Date(s) Tested  : 2025-10-28
Tested By       : Alexis McGuire
Systems Tested  : Windows 11 (PowerShell 5.1)
PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
This script checks and enforces the WinRM Client 'AllowBasic' registry setting to ensure it is set to 0 (disabled).

Example syntax:

PS C:\> .\__remediation_template(WN11-CC-000330).ps1
#>

# =====================================================================
# STIG ID: WN11-CC-000330 - WinRM Client AllowBasic = 0
# =====================================================================
Write-Host "`n[WN11-CC-000330] Checking WinRM Client 'AllowBasic'..." -ForegroundColor Cyan

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowBasic"
$desiredValue = 0

try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "Registry path created: $regPath" -ForegroundColor Yellow
    }

    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
        Write-Host "Incorrect or missing value. Fixing..." -ForegroundColor Yellow
        New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
        Write-Host "✅ Success: AllowBasic set to 0 (Disabled)." -ForegroundColor Green
    } else {
        Write-Host "✅ Success: AllowBasic is already compliant (0)." -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Fail: Unable to set WinRM Client AllowBasic." -ForegroundColor Red
}
