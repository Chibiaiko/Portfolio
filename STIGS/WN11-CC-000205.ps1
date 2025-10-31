<#
.SYNOPSIS
    Apply STIG WN11-CC-000205: set HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry to 0 (Security) or 1 (Basic).

.NOTES
    Author         : Alexis McGuire
    LinkedIn       : linkedin.com/in/alexismcguire1/
    GitHub         : github.com/Chibiaiko
    Date Created   : 2025-10-24
    Last Modified  : 2025-10-24
    Version        : 1.0
    CVEs           : N/A
    Plugin IDs     : N/A
    STIG-ID        : WN11-CC-000205

.TESTED ON
    Date(s) Tested  : 2025-10-24
    Tested By       : Alexis McGuire
    Systems Tested  : Windows 11 (PowerShell 5.1)
    PowerShell Ver. : Windows PowerShell 5.1 (ISE)

.USAGE
  Put any usage instructions here.

Example syntax:
    PS C:\> .\WN11_CC_000205.ps1 -Level 0
    PS C:\> .\WN11_CC_000205.ps1 -Level 1 -WhatIf
#>

param(
    [ValidateSet(0,1)]
    [int]$Level = 0,

    [switch]$WhatIf
)

function Assert-RunningAsAdmin {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function Set-RegistryDword {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [Microsoft.Win32.RegistryView]$View,
        [switch]$WhatIf
    )

    $action = "Setting $Name = $Value in $View view at HKLM:\$Path"
    if ($WhatIf) { Write-Output "[WhatIf] $action"; return }

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $View)
        $regKey = $baseKey.CreateSubKey($Path)
        $regKey.SetValue($Name, [int]$Value, [Microsoft.Win32.RegistryValueKind]::DWord)
        $regKey.Close()
        Write-Output "[$View] $Name set to $Value successfully."
    } catch {
        Write-Error "Failed to set $Name in $View view: $_"
    }
}

# --- Main ---
Assert-RunningAsAdmin

$regPath = "SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName = "AllowTelemetry"

$views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)

foreach ($view in $views) {
    # Read current value without using ?. operator
    $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view).OpenSubKey($regPath)
    if ($regKey) {
        $current = $regKey.GetValue($valueName)
        $regKey.Close()
    } else {
        $current = $null
    }

    if ($current -eq $null) {
        Write-Output "[$view] Current value: (not present)"
    } else {
        Write-Output "[$view] Current value: $current"
    }

    if ($current -ne $Level) {
        Set-RegistryDword -Path $regPath -Name $valueName -Value $Level -View $view -WhatIf:$WhatIf
    } else {
        Write-Output "[$view] Already set to desired value ($Level)."
    }
}

Write-Output "`nTelemetry setting applied: $Level (0 = Security, 1 = Basic)"
