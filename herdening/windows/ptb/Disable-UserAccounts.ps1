Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exemptPath = Join-Path $scriptDir "exempt.txt"
$exempt = @()
if (Test-Path $exemptPath) {
    $exempt = Get-Content $exemptPath |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") }
}

function Test-Administrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

# DomainRole: 4 = Backup Domain Controller, 5 = Primary Domain Controller.
$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDomainController = $domainRole -in 4, 5
if (-not $isDomainController) {
    $ntds = Get-Service -Name NTDS -ErrorAction SilentlyContinue
    if ($ntds) {
        $isDomainController = $true
    }
}

if ($isDomainController) {
    Import-Module ActiveDirectory
    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties Enabled |
        Where-Object { $_.Enabled -eq $true -and $_.SamAccountName -notin $exempt }

    $disabled = 0
    foreach ($user in $users) {
        Disable-ADAccount -Identity $user.SamAccountName -Confirm:$false
        $disabled++
    }
    Write-Host ("Disabled {0} domain accounts." -f $disabled)
} else {
    $users = Get-LocalUser |
        Where-Object { $_.Enabled -eq $true -and $_.Name -notin $exempt }

    $disabled = 0
    foreach ($user in $users) {
        Disable-LocalUser -Name $user.Name -Confirm:$false
        $disabled++
    }
    Write-Host ("Disabled {0} local accounts." -f $disabled)
}
