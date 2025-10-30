<#
.SYNOPSIS
    Disables IPv6 source routing by setting "DisableIpSourceRouting" to 2 for maximum protection.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-27
    Last Modified   : 2025-10-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000020

.TESTED ON
    Date(s) Tested  : 2025-10-27
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Disables IPv6 source routing to prevent packet redirection attacks.
    Example:
    PS C:\> .\WN11-CC-000020_DisableIPv6SourceRouting.ps1
#>

# Set DisableIpSourceRouting to 2 (Highest protection, completely disabled)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$regName = "DisableIpSourceRouting"
$regValue = 2

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

# Verify
Get-ItemProperty -Path $regPath -Name $regName

