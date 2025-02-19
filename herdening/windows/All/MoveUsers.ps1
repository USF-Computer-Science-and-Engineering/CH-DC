param(
    [string]$action = "remove",
    [string]$users = "C:\Path\To\baduser.txt",
    [string]$group
)

function MoveUsers($group, $users, $add) {
    $usersList = Get-Content $users

    $changeType = if ($add -eq $false) { "removed from" } else { "added to" }

    foreach ($user in $usersList) {
        try {
            if ($add -eq $false) {
                Remove-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
                Write-Host "User '$user' $changeType $group."
            } else {
                Add-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
                Write-Host "User '$user' $changeType $group."
            }
        } catch {
            Write-Host "Failed to perform the operation for user '$user' in group '$group'. $_"
        }
    }
}

if (-not $group) {
    $group = Read-Host "Enter the name of the group to manage"
}

if ($action -eq "remove") {
    MoveUsers $group $users $false
} elseif ($action -eq "add") {
    MoveUsers $group $users $true
} else {
    Write-Host "Invalid argument. Use 'add' to add users or 'remove' to remove users from the group."
}
