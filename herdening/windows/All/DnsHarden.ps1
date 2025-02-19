# Ensure the script is run with Administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "Please run PowerShell as an Administrator."
    Break
}

# Backup DNS Configuration
Export-Clixml -Path "C:\DNSBackup\DNSConfigBackup.xml" -InputObject (Get-DnsServerZone)

# Restore DNS Configuration
# Import-Clixml -Path "C:\DNSBackup\DNSConfigBackup.xml" | ForEach-Object { Set-DnsServerZone $_ }

# Mitigate LLMNR Poisoning
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force

# Disable IPv6 on all adapters
Get-NetAdapter | ForEach-Object { Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6 -Confirm:$false }
