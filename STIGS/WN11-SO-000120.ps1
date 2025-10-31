<#
.SYNOPSIS
    Enables SMB server digital signing by setting "RequireSecuritySignature" to 1.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-27
    Last Modified   : 2025-10-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000120

.TESTED ON
    Date(s) Tested  : 2025-10-27
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Ensures SMB server communications are digitally signed for integrity protection.
    
    Example syntax:
        PS C:\> .\WN11-SO-000120_EnableSMBSigning.ps1
#>

# Set RequireSecuritySignature to 1 (Require SMB server signing)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$regName = "RequireSecuritySignature"
$regValue = 1

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

Write-Host "Enabled SMB server digital signing (RequireSecuritySignature = 1)."

# Verification
$requireSig = Get-ItemProperty -Path $regPath -Name $regName
Write-Host "`nVerification:"
Write-Host "SMB server RequireSecuritySignature value: $($requireSig.$regName)"
