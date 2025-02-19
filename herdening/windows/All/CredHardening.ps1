# Ensure the script is run with Administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "Please run PowerShell as an Administrator."
    Break
}

# Check for and remove GPP passwords in SYSVOL
# Prompt the user for the FQDN
$fqdn = Read-Host "Please enter the Fully Qualified Domain Name (FQDN)"

# Construct the SYSVOL path using the user-provided FQDN
$sysvolPath = "\\$fqdn\SYSVOL\$fqdn\Policies"

Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" | ForEach-Object {
    $content = Get-Content $_.FullName
    if ($content -match "<cpassword>")
    {
        Write-Host "Found GPP password in file: $($_.FullName)"
        # Remove or secure the file appropriately
    }
}

# Enable LSA protections
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type Dword

# Disable WDigest
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

# Disable storage of plain text passwords in AD via GPO
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord

# Disable password caching
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0

Write-Host "Hardening tasks completed."