

Import-Module ActiveDirectory

param(
    [string]$action = "add",       
    [string[]]$ignoreUsers = @()     
)


$dangerousPrivileges = @(
    "SeDebugPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege",
    "SeCreateTokenPrivilege",
    "SeIncreaseQuotaPrivilege"
)


function Remove-Privileges {
    param(
        [string]$user,
        [string]$userType  
    )

    foreach ($privilege in $dangerousPrivileges) {
        try {
            if ($userType -eq "Local") {
                $userObj = Get-LocalUser $user -ErrorAction Stop
            } else {
                $userObj = Get-ADUser -Identity $user -Properties SamAccountName -ErrorAction Stop
            }


            if ($ignoreUsers -contains $userObj.SamAccountName) {
                Write-Host "User $($userObj.SamAccountName) is in the ignore list. Skipping."
                continue
            }

            $privilegeName = "Se" + $privilege


            if ($action -eq "add") {

                $userObj | Remove-LocalGroupMember -Group $privilegeName -ErrorAction Stop
                Write-Host "Removed '$privilegeName' privilege from $($userObj.SamAccountName) successfully."
            } elseif ($action -eq "revert") {

                $userObj | Add-LocalGroupMember -Group $privilegeName -ErrorAction Stop
                Write-Host "Reverted '$privilegeName' privilege for $($userObj.SamAccountName) successfully."
            }
        } catch {
            Write-Host "Failed to process $($userObj.SamAccountName). $_"
        }
    }
}


$localUsers = Get-LocalUser


foreach ($user in $localUsers) {
    Remove-Privileges -user $user.Name -userType "Local"
}

$domainUsers = Get-ADUser -Filter * -Properties SamAccountName

foreach ($user in $domainUsers) {
    Remove-Privileges -user $user.SamAccountName -userType "Domain"
}
