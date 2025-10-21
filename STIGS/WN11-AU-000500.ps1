<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Alexis McGuire
    LinkedIn        : linkedin.com/in/alexismcguire1/
    GitHub          : github.com/Chibiaiko
    Date Created    : 2025-10-21
    Last Modified   : 2025-10-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Save this script as: WN11-AU-000500.ps1
    Run PowerShell ISE as Administrator, then press F5 to execute.
    Example syntax:
    PS C:\> .\WN11-AU-000500.ps1
#>

# --- Ensure running as Administrator ---
$adminCheck = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $adminCheck) {
    Write-Host "Restarting script as Administrator..."
    Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit
}

# --- Registry update ---
$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 0x00008000  # 32 MB (32768 KB)

# Create the key if it doesn’t exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Created registry path: $regPath"
}

# Apply the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord
Write-Host "Set '$valueName' to $valueData (32 MB)."

# --- Verify result ---
$verify = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Host "Verification: [$regPath] '$valueName' = $verify (0x$("{0:X}" -f $verify))"

# --- Optional friendly message ---
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("MaxSize successfully set to 32 MB.", "WN11-AU-000500 Applied", "OK", "Information")
