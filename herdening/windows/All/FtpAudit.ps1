$ftpRoot = "C:\inetpub\ftproot" # Change this path to your FTP root
$backupDirectory = "C:\ftpbackup" # Specify your backup directory path

# Ensure the backup directory exists
if (-not (Test-Path -Path $backupDirectory)) {
    New-Item -ItemType Directory -Path $backupDirectory
}

# Backup files from FTP root to backup directory
Copy-Item -Path "$ftpRoot\*" -Destination $backupDirectory -Recurse -Force

# Get list of files and select required properties
$files = Get-ChildItem -Path $ftpRoot -Recurse | Select-Object FullName, Length, LastWriteTime

# Output the files list to a text file in C:\
$files | Out-File -FilePath "C:\FTPFiles.txt"

# Optionally, if you want to see the output on the console as well
$files | Format-Table -AutoSize

Write-Host "Files have been backed up and listed in C:\FTPFiles.txt"