
Import-Module ActiveDirectory

param(
    [string]$action = "apply",  
    [string]$ignoreUsers = ""  
)

$userType = Read-Host "Enter 'Local' or 'Domain' to manage local or domain users"
while ($userType -ne "Local" -and $userType -ne "Domain") {
    Write-Host "Invalid choice. Please enter 'Local' or 'Domain'."
    $userType = Read-Host "Enter 'Local' or 'Domain' to manage local or domain users"
}

$newPassword = Read-Host "Enter the new password" -AsSecureString

$changedUsers = @()

if ($userType -eq "Local") {
    $allUsers = Get-LocalUser
} else {
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName
}

foreach ($user in $allUsers) {
    if ($ignoreUsers -split ',' -contains $user.Name) {
        Write-Host "Ignoring user '$($user.Name)'."
        continue
    }

    try {
        if ($userType -eq "Local") {
            if ($action -eq "apply") {
                Set-LocalUser -Name $user.Name -Password $newPassword -ErrorAction Stop -Confirm:$false
                $changedUsers += [PSCustomObject]@{
                    UserName = $user.Name
                    UserType = "Local"
                }
            } elseif ($action -eq "revert") {
                Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -ErrorAction Stop -Confirm:$false
                $changedUsers += [PSCustomObject]@{
                    UserName = $user.Name
                    UserType = "Local"
                }
            }
        } else {
            $adUser = Get-ADUser -Identity $user.SamAccountName
            if ($action -eq "apply") {
                Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword $newPassword -Reset -ErrorAction Stop
                $changedUsers += [PSCustomObject]@{
                    UserName = $adUser.SamAccountName
                    UserType = "Domain"
                }
            } elseif ($action -eq "revert") {
                Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -Reset -ErrorAction Stop
                $changedUsers += [PSCustomObject]@{
                    UserName = $adUser.SamAccountName
                    UserType = "Domain"
                }
            }
        }
    } catch {
        Write-Host "Failed to perform the operation for user '$($user.Name)'. $_"
    }
}

Write-Host "`nList of Changed Users:"
$changedUsers | Format-Table -AutoSize
