<#
.SYNOPSIS
    Ensures the NoGPOListChanges registry value is set to 0 to comply with STIG ID: WN11-CC-000090.

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-22
    Last Modified   : 2025-10-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090

.TESTED ON
    Date(s) Tested  : 2025-10-22
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
    Run this script with administrative privileges to ensure the registry key is set per STIG requirements.
   
    Example syntax:
    PS C:\> .\Set-NoGPOListChanges.ps1
#>

# Define registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName = "NoGPOListChanges"
$valueData = 0

try {
    # Ensure parent key exists
    $parentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
    if (-not (Test-Path $parentPath)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Group Policy" -Force | Out-Null
    }

    # Create GUID key if missing
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $parentPath -Name "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Force | Out-Null
    }

    # Set the DWORD value
    New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verify the value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName).$valueName

    if ($currentValue -eq $valueData) {
        Write-Output "SUCCESS: Registry key $registryPath\$valueName set to $valueData"
    } else {
        Write-Output "ERROR: Registry value $valueName was not set correctly. Current value: $currentValue"
    }

} catch {
    Write-Output "ERROR: Failed to update registry. $_"
}
