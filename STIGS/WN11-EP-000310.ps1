<#
.SYNOPSIS
    Configures Kernel DMA Protection by setting DeviceEnumerationPolicy to 0 
    in the registry to disable automatic device enumeration.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-23
    Last Modified   : 2025-10-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.TESTED ON
    Date(s) Tested  : 2025-10-23
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Run PowerShell as Administrator.
   
    Example syntax:
        PS C:\> .\Set-DeviceEnumerationPolicy.ps1
#>

# Define the registry path and value
$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
$valueName = "DeviceEnumerationPolicy"
$valueData = 0

# Check if the registry key exists, create it if it does not
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Output "Registry value '$valueName' set to $valueData at $registryPath"
