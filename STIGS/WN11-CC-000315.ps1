<#
.SYNOPSIS
    Disables AlwaysInstallElevated to prevent MSI packages from installing with elevated privileges 
    by setting the registry value to 0.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-23
    Last Modified   : 2025-10-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 2025-10-23
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Run PowerShell as Administrator.
    Example syntax:
    PS C:\> .\Set-AlwaysInstallElevated.ps1
#>

# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"
$valueData = 0

# Check if the registry key exists, create it if not
if (-not (Test-Path $registryPath)) {
    New-Item -Path $regis
