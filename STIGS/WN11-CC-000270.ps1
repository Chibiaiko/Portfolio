<#
.SYNOPSIS
    Prevents the saving of Remote Desktop passwords by setting "DisablePasswordSaving" to 1.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-27
    Last Modified   : 2025-10-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000270

.TESTED ON
    Date(s) Tested  : 2025-10-27
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Disables the saving of Remote Desktop passwords to enhance credential security.
    Example:
    PS C:\> .\WN11-CC-000270_DisablePasswordSaving.ps1
#>

# Set DisablePasswordSaving to 1 (Do not allow passwords to be saved)
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$regName = "DisablePasswordSaving"
$regValue = 1

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

# Verify
Get-ItemProperty -Path $regPath -Name $regName
