function Get-GroupMembers {
    param (
        [string]$groupName
    )

    $groupMembers = Get-ADGroupMember -Identity $groupName | Select-Object Name, SamAccountName, DistinguishedName
    $groupMembers
}

function List-ADGroupMembers {
    $allGroups = Get-ADGroup -Filter * -Properties Name

    foreach ($group in $allGroups) {
        $groupName = $group.Name
        Write-Host "Members of $groupName:"
        Get-GroupMembers -groupName $groupName | Format-Table
        Write-Host ""
    }
}

function List-LocalGroupMembers {
    $localGroups = Get-LocalGroup | Select-Object Name

    foreach ($localGroup in $localGroups) {
        $localGroupName = $localGroup.Name
        Write-Host "Members of local group $localGroupName:"
        Get-GroupMembers -groupName $localGroupName | Format-Table
        Write-Host ""
    }
}

List-ADGroupMembers

List-LocalGroupMembers
