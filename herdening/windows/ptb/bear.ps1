param (
    [switch]$restore
)


$folders = @(
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot\System32"
)


$outputDir = "C:\tools\logs\ACL_Backups"
if (!(Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}


function Backup-ACLs {
    foreach ($folder in $folders) {
        $outputFile = Join-Path -Path $outputDir -ChildPath ("$(Split-Path -Leaf $folder)_ACLs.csv")
        try {
            Get-ChildItem -Path $folder -Recurse | ForEach-Object {
                $acl = Get-Acl $_.FullName
                [PSCustomObject]@{
                    Path = $_.FullName
                    SDDL = $acl.Sddl
                }
            } | Export-Csv -Path $outputFile -NoTypeInformation
            Write-Output "ACL backup for $folder saved to $outputFile"
        } catch {
            Write-Error ("Failed to backup ACL for {0}: {1}" -f $folder, $_.Exception.Message)
        }
    }
}


function Restore-ACLs {
    param (
        [string]$BackupFile
    )

    if (!(Test-Path -Path $BackupFile)) {
        Write-Error "Backup file not found: $BackupFile"
        return
    }

    Import-Csv -Path $BackupFile | ForEach-Object {
        try {
            $currentAcl = Get-Acl $_.Path
            if ($currentAcl.Sddl -ne $_.SDDL) {
                $newAcl = Get-Acl $_.Path
                $newAcl.SetSecurityDescriptorSddlForm($_.SDDL)
                Set-Acl -Path $_.Path -AclObject $newAcl
                Write-Output "Restored ACL for: $($_.Path)"
            } else {
               
            }
        } catch {
            Write-Error ("Failed to restore ACL for {0}: {1}" -f $_.Path, $_.Exception.Message)
        }
    }
}


if ($restore) {
    Write-Output "Starting ACL restore process..."
    Restore-ACLs -BackupFile "$outputDir\SysWOW64_ACLs.csv"
    Restore-ACLs -BackupFile "$outputDir\System32_ACLs.csv"
    Write-Output "Restore process completed."
} else {
    Write-Output "Starting ACL backup process..."
    Backup-ACLs
    Write-Output "Backup process completed."
}
