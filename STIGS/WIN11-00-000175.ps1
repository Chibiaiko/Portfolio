<#
.SYNOPSIS
    Remediates STIG WIN11-00-000175 by disabling the Secondary Logon service.

.NOTES
    Author       : Alexis McGuire
    LinkedIn     : linkedin.com/in/alexismcguire1/
    GitHub       : github.com/Chibiaiko
    Date Created : 2025-10-24
    Last Modified: 2025-10-24
    Version      : 1.0
    CVEs         : N/A
    Plugin IDs   : N/A
    STIG-ID      : WIN11-00-000175

.TESTED ON
    Date(s) Tested  : 2025-10-24
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)
    
.USAGE
    Put any usage instructions here.

    Example syntax:
        PS C:\> .\__remediation_template(WIN11-00-000175).ps1
#>


# Disable Secondary Logon service (STIG WIN11-00-000175)
$serviceName = "seclogon"

# Set the service Startup Type to Disabled
Set-Service -Name $serviceName -StartupType Disabled

# Stop the service if it's currently running
if ((Get-Service -Name $serviceName).Status -eq 'Running') {
    Stop-Service -Name $serviceName -Force
}

# Verify the change
$service = Get-Service -Name $serviceName
if ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped') {
    Write-Output "Success: Secondary Logon service is Disabled and Stopped."
} else {
    Write-Output "Failed: Secondary Logon service is not properly configured."
}
