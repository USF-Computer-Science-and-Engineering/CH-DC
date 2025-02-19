param (
    [string]$action
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as an administrator to manage Kerberos pre-authentication."
    Exit
}
$kerberosPreAuthRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

function Apply-KerberosPreAuthChange {
    if (-not (Test-Path $kerberosPreAuthRegistryPath)) {
        New-Item -Path $kerberosPreAuthRegistryPath -Force | Out-Null
    }

    if (-not (Test-Path "$kerberosPreAuthRegistryPath\AllowPreauth")) {
        New-ItemProperty -Path $kerberosPreAuthRegistryPath -Name "AllowPreauth" -Value 0 -PropertyType DWORD -Force
    }

    Set-ItemProperty -Path $kerberosPreAuthRegistryPath -Name "AllowPreauth" -Value 0 -Force

    Write-Host "Kerberos pre-authentication has been disabled."
}

function Revert-KerberosPreAuthChange {
    if (Test-Path "$kerberosPreAuthRegistryPath\AllowPreauth") {
        Set-ItemProperty -Path $kerberosPreAuthRegistryPath -Name "AllowPreauth" -Value 1 -Force

        Write-Host "Kerberos pre-authentication has been enabled."
    } else {
        Write-Host "Kerberos pre-authentication change not found. No action taken."
    }
}

switch ($action) {
    "apply" { Apply-KerberosPreAuthChange }
    "revert" { Revert-KerberosPreAuthChange }
    default { Write-Host "Invalid action. Use -action apply to disable Kerberos pre-authentication or -action revert to revert the change." }
}
