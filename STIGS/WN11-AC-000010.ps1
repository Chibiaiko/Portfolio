<#
.SYNOPSIS
Remediates and verifies that the Account Lockout Threshold is set to 3 or less, in accordance with STIG requirements.

.NOTES
Author        : Alexis McGuire
LinkedIn      : linkedin.com/in/alexismcguire1/
GitHub        : github.com/Chibiaiko
Date Created  : 2025-10-28
Last Modified : 2025-10-28
Version       : 1.0
CVEs          : N/A
Plugin IDs    : N/A
STIG-ID       : WN11-AC-000010

.TESTED ON
Date(s) Tested :
Tested By      :
Systems Tested :
PowerShell Ver. :

.USAGE
This script checks and enforces the Account Lockout Threshold policy to ensure it is set to 3 or less and not 0.

Example syntax:

PS C:\> .\__remediation_template(WN11-AC-000010).ps1
#>

# =====================================================================
# STIG ID: WN11-AC-000010 - Account lockout threshold <= 3 and not 0
# =====================================================================
Write-Host "`n[WN11-AC-000010] Checking Account Lockout Threshold..." -ForegroundColor Cyan

try {
    # Try to read current threshold from local security policy
    $tempFile = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $tempFile | Out-Null
    $lockoutThreshold = (Select-String "LockoutBadCount" $tempFile).ToString().Split("=")[1].Trim()
    Remove-Item $tempFile -Force

    if ([int]$lockoutThreshold -eq 0 -or [int]$lockoutThreshold -gt 3) {
        Write-Host "Current threshold: $lockoutThreshold - Incorrect. Fixing..." -ForegroundColor Yellow
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        (Get-Content "$env:TEMP\secpol.cfg") -replace 'LockoutBadCount = \d+', 'LockoutBadCount = 3' | Set-Content "$env:TEMP\secpol.cfg"
        secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
        Remove-Item "$env:TEMP\secpol.cfg","$env:TEMP\secedit.sdb" -Force -ErrorAction SilentlyContinue
        Write-Host "✅ Success: Account lockout threshold set to 3." -ForegroundColor Green
    } else {
        Write-Host "✅ Success: Account lockout threshold is compliant ($lockoutThreshold)." -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Fail: Unable to check or configure account lockout threshold." -ForegroundColor Red
}
