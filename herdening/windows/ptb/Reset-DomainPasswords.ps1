param(
    [string[]]$e
)

Import-Module ActiveDirectory -ErrorAction Stop

$logPath = Join-Path -Path $PSScriptRoot -ChildPath ("password-reset-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message
    Write-Host $line
    Add-Content -Path $logPath -Value $line
}

# Build exclusion set from -e (comma-separated supported)
$excludeSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if ($e) {
    foreach ($token in $e) {
        foreach ($name in ($token -split ',')) {
            $name = $name.Trim()
            if ($name) { [void]$excludeSet.Add($name) }
        }
    }
}

Write-Log "Starting domain password reset."
Write-Log ("Log file: {0}" -f $logPath)

if ($excludeSet.Count -gt 0) {
    Write-Log ("Excluding {0} username(s): {1}" -f $excludeSet.Count, (($excludeSet | Sort-Object) -join ', ')) "WARN"
}

$userPassword  = Read-Host "Enter the password to set for all domain users" -AsSecureString
$adminPassword = Read-Host "Enter the password to set for all Domain Admins" -AsSecureString

Write-Log "Fetching domain users (excluding computer accounts, Domain Admins, KRBTGT, and -e exclusions)."

$domainAdminDns = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $_.objectClass -eq "user" } |
    Select-Object -ExpandProperty DistinguishedName

$domainAdminDnSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($dn in $domainAdminDns) { [void]$domainAdminDnSet.Add($dn) }

$domainUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -Properties SamAccountName, DistinguishedName |
    Where-Object {
        -not $domainAdminDnSet.Contains($_.DistinguishedName) -and
        $_.SamAccountName -ne "krbtgt" -and
        -not $excludeSet.Contains($_.SamAccountName)
    }

foreach ($user in $domainUsers) {
    try {
        Set-ADAccountPassword -Identity $user.DistinguishedName -Reset -NewPassword $userPassword -ErrorAction Stop
        Write-Log ("Set password for user: {0}" -f $user.SamAccountName)
    } catch {
        Write-Log ("Failed to set password for user: {0}. Error: {1}" -f $user.SamAccountName, $_.Exception.Message) "ERROR"
    }
}

Write-Log "Fetching Domain Admins (users only, excluding KRBTGT and -e exclusions)."

$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object {
        $_.objectClass -eq "user" -and
        $_.SamAccountName -ne "krbtgt" -and
        -not $excludeSet.Contains($_.SamAccountName)
    }

foreach ($admin in $domainAdmins) {
    try {
        Set-ADAccountPassword -Identity $admin.DistinguishedName -Reset -NewPassword $adminPassword -ErrorAction Stop
        Write-Log ("Set password for Domain Admin: {0}" -f $admin.SamAccountName)
    } catch {
        Write-Log ("Failed to set password for Domain Admin: {0}. Error: {1}" -f $admin.SamAccountName, $_.Exception.Message) "ERROR"
    }
}

Write-Log "Completed domain password reset."
