
Import-Module ActiveDirectory

param(
    [string]$action = "add" 
)


$adminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")

$sensitiveUsers = Get-ADGroupMember -Identity $adminGroups -Recursive | Select-Object -ExpandProperty SamAccountName

foreach ($user in $sensitiveUsers) {
    try {
        if ($action -eq "add") {
            Set-ADUser -Identity $user -CannotBeDelegate $true
            Write-Host "User '$user' marked as 'User cannot be delegate' successfully."
        } elseif ($action -eq "revert") {
            Set-ADUser -Identity $user -CannotBeDelegate $false
            Write-Host "Reverted 'User cannot be delegate' setting for user '$user' successfully."
        }
    } catch {
        Write-Host "Failed to perform the operation for user '$user'. $_"
    }
}
