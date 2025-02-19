Import-Module ActiveDirectory

param(
    [string]$action = "apply",
    [string]$ignore
)

$sensitiveGroups = @("Domain Admins", "Enterprise Admins", "Administrators")

$sensitiveUsers = Get-ADGroupMember -Identity $sensitiveGroups -Recursive | Select-Object -ExpandProperty SamAccountName

$usersToIgnore = @()
if ($ignore) {
    $usersToIgnore = $ignore -split ','
}

foreach ($user in $sensitiveUsers) {
    if ($usersToIgnore -contains $user.SamAccountName) {
        Write-Host "User '$($user.SamAccountName)' is ignored."
        continue
    }

    try {
        if ($action -eq "apply") {
            Add-ADGroupMember -Identity "Protected Users" -Members $user.SamAccountName -ErrorAction Stop
            Write-Host "User '$($user.SamAccountName)' added to 'Protected Users' group successfully."
        } elseif ($action -eq "revert") {
            Remove-ADGroupMember -Identity "Protected Users" -Members $user.SamAccountName -ErrorAction Stop
            Write-Host "User '$($user.SamAccountName)' removed from 'Protected Users' group successfully."
        }
    } catch {
        Write-Host "Failed to perform the operation for user '$($user.SamAccountName)'. $_"
    }
}
