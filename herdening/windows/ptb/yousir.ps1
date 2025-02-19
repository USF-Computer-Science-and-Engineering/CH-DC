$usersFile = "users.txt"
$adminsFile = "admins.txt"
$logFile = "C:\\tools\\logs\\yousir.log"

Function Log-Message($message) {
    Write-Output $message
    "$message" | Out-File -FilePath $logFile -Append
}

$choice = Read-Host "Do you want to change Local (L) or Domain (D) passwords? (L/D)"
$isDomain = $choice -eq "D"

$users = Get-Content $usersFile
$admins = Get-Content $adminsFile

Function Get-ConfirmedPassword($prompt) {
    do {
        $password = Read-Host "$prompt" -AsSecureString
        $confirmPassword = Read-Host "Confirm $prompt" -AsSecureString
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $confirmText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))
        if ($passwordText -ne $confirmText) {
            Write-Output "Passwords do not match. Please try again."
        }
    } while ($passwordText -ne $confirmText)
    return $password
}

$newUserPassword = Get-ConfirmedPassword "Enter new password for users"
$newAdminPassword = Get-ConfirmedPassword "Enter new password for admins"

Log-Message "Starting group management operations."


if ($isDomain) {
    foreach ($admin in $admins) {
        $inGroup = Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -eq $admin }
        if (-not $inGroup) {
            try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $admin -Confirm:$false -ErrorAction Stop
                Log-Message ("Added {0} to Domain Admins." -f $admin)
            } catch {
                Log-Message ("Failed to add {0} to Domain Admins: {1}" -f $admin, $_)
            }
        }
    }
}


$allAdminGroups = if ($isDomain) {
    Get-ADGroup -Filter 'Name -like "*Admin*"' | Select-Object -ExpandProperty Name
} else {
    Get-LocalGroup | Where-Object { $_.Name -match "Admin" } | Select-Object -ExpandProperty Name
}

foreach ($group in $allAdminGroups) {
    foreach ($user in $users) {
        $inGroup = if ($isDomain) {
            Get-ADGroupMember -Identity $group | Where-Object { $_.SamAccountName -eq $user }
        } else {
            Get-LocalGroupMember -Group $group | Where-Object { $_.Name -eq $user }
        }
        if ($inGroup) {
            try {
                if ($isDomain) {
                    Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
                } else {
                    Remove-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
                }
                Log-Message ("Removed {0} from {1}." -f $user, $group)
            } catch {
                Log-Message ("Failed to remove {0} from {1}: {2}" -f $user, $group, $_)
            }
        }
    }
}


$existingUsers = if ($isDomain) {
    Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
} else {
    Get-LocalUser | Select-Object -ExpandProperty Name
}

$unknownUsers = $existingUsers | Where-Object { $_ -notin $users -and $_ -notin $admins -and $_ -notmatch '\\\\$' }

if ($unknownUsers) {
    Write-Output "--- Users not in either list ---"
    $unknownUsers | ForEach-Object { Write-Output $_ }
    $disableChoice = Read-Host "Do you want to disable any of these users? (y/n)"
    if ($disableChoice -eq "y") {
        foreach ($unknownUser in $unknownUsers) {
            $response = Read-Host "Disable $unknownUser? (y/n)"
            if ($response -eq "y") {
                try {
                    if ($isDomain) {
                        Disable-ADAccount -Identity $unknownUser -Confirm:$false
                    } else {
                        Disable-LocalUser -Name $unknownUser -Confirm:$false
                    }
                    Log-Message ("{0} has been disabled." -f $unknownUser)
                } catch {
                    Log-Message ("Failed to disable {0}: {1}" -f $unknownUser, $_)
                }
            }
        }
    }
}

Log-Message "Group management and user checks completed."
