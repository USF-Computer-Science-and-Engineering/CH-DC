param (
    [string]$action
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as an administrator to manage RC4 encryption for Kerberos."
    Exit
}

$kerberosRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

function Apply-RC4Change {
    if (-not (Test-Path $kerberosRegistryPath)) {
        New-Item -Path $kerberosRegistryPath -Force | Out-Null
    }

    if (-not (Test-Path "$kerberosRegistryPath\SupportedEncryptionTypes")) {
        New-ItemProperty -Path $kerberosRegistryPath -Name "SupportedEncryptionTypes" -Value 0 -PropertyType DWORD -Force
    }

    Set-ItemProperty -Path $kerberosRegistryPath -Name "SupportedEncryptionTypes" -Value 0x18 -Force

    Write-Host "RC4 encryption has been disabled for Kerberos."
}

function Revert-RC4Change {
    if (Test-Path "$kerberosRegistryPath\SupportedEncryptionTypes") {
        Set-ItemProperty -Path $kerberosRegistryPath -Name "SupportedEncryptionTypes" -Value 0 -Force

        Write-Host "RC4 encryption has been enabled for Kerberos."
    } else {
        Write-Host "RC4 encryption change not found. No action taken."
    }
}

switch ($action) {
    "apply" { Apply-RC4Change }
    "revert" { Revert-RC4Change }
    default { Write-Host "Invalid action. Use -action apply to disable RC4 or -action revert to revert the change." }
}
