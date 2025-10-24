<#
.SYNOPSIS
  Apply STIG WN11-CC-000200: set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators to 0 (REG_DWORD).

.NOTES
Author : Alexis McGuire
LinkedIn : linkedin.com/in/alexismcguire1/
GitHub : github.com/Chibiaiko
Date Created : 2025-10-24 
Last Modified : 2025-10-24 
Version : 1.0
CVEs : N/A
Plugin IDs : N/A
STIG-ID : WN11-CC-000200

.TESTED ON
Date(s) Tested :
Tested By :
Systems Tested :
PowerShell Ver. :

.USAGE
Put any usage instructions here.

Example syntax:
PS C:\> .\WN11_CC_000200.ps1 -WhatIf

#>

param(
    [switch]$WhatIf
)

function Assert-RunningAsAdmin {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run elevated (as Administrator). Exiting."
        exit 1
    }
}

function Get-RegistryDwordValue {
    param(
        [Microsoft.Win32.RegistryHive]$Hive = [Microsoft.Win32.RegistryHive]::LocalMachine,
        [string]$SubKey,
        [string]$ValueName,
        [Microsoft.Win32.RegistryView]$View
    )
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $View)
        $key = $baseKey.OpenSubKey($SubKey)
        if ($null -eq $key) { return $null }
        return $key.GetValue($ValueName)
    } catch {
        Write-Verbose "Error reading registry: $_"
        return $null
    }
}

function Set-RegistryDwordValue {
    param(
        [Microsoft.Win32.RegistryHive]$Hive = [Microsoft.Win32.RegistryHive]::LocalMachine,
        [string]$SubKey,
        [string]$ValueName,
        [int]$ValueData,
        [Microsoft.Win32.RegistryView]$View,
        [switch]$WhatIf
    )
    $action = "Set $ValueName = $ValueData in $View view at HKLM:\$SubKey"
    if ($WhatIf) {
        Write-Output "[WhatIf] $action"
        return $true
    }

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $View)
        $writableKey = $baseKey.CreateSubKey($SubKey)
        if ($null -eq $writableKey) {
            Write-Error "Failed to open or create HKLM:\$SubKey in $View view."
            return $false
        }
        $writableKey.SetValue($ValueName, [int]$ValueData, [Microsoft.Win32.RegistryValueKind]::DWord)
        $writableKey.Close()
        return $true
    } catch {
        Write-Error "Failed to set registry value in $View view: $_"
        return $false
    }
}

# --- Script main ---
$regPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$valueName = "EnumerateAdministrators"
$desiredValue = 0

Assert-RunningAsAdmin

$views = @(
    [Microsoft.Win32.RegistryView]::Registry64,
    [Microsoft.Win32.RegistryView]::Registry32
)

$results = @()

foreach ($view in $views) {
    $current = Get-RegistryDwordValue -SubKey $regPath -ValueName $valueName -View $view
    if ($null -eq $current) {
        Write-Output "[$view] Current value: (not present)"
    } else {
        Write-Output "[$view] Current value: $current"
    }

    if ($current -ne $desiredValue) {
        $ok = Set-RegistryDwordValue -SubKey $regPath -ValueName $valueName -ValueData $desiredValue -View $view -WhatIf:$WhatIf
        if ($ok) {
            if (-not $WhatIf) {
                $new = Get-RegistryDwordValue -SubKey $regPath -ValueName $valueName -View $view
                Write-Output "[$view] New value: $new"
                $results += @{ View = $view; Changed = $true; NewValue = $new }
            } else {
                $results += @{ View = $view; Changed = $false; NewValue = "WhatIf - no change" }
            }
        } else {
            $results += @{ View = $view; Changed = $false; NewValue = "Failed" }
        }
    } else {
        Write-Output "[$view] Already set to desired value ($desiredValue)."
        $results += @{ View = $view; Changed = $false; NewValue = $current }
    }
}

# Summary
Write-Output "`nSummary:"
foreach ($r in $results) {
    $v = $r.View.ToString().Split('+')[-1]
    Write-Output (" - {0}: Changed={1}, Value={2}" -f $v, $r.Changed, $r.NewValue)
}

# Exit with non-zero code if any write failed (only relevant when not WhatIf)
if (-not $WhatIf) {
    $failed = $results | Where-Object { $_.NewValue -eq "Failed" }
    if ($failed) { exit 2 } else { exit 0 }
} else {
    exit 0
}


